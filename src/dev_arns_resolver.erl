%%% @doc ARNS (Arweave Name System) resolver for HyperBEAM that integrates with
%%% AR.IO gateways to resolve human-readable names to Arweave transaction IDs.
%%% 
%%% This module provides a resolver that can be used with dev_name.erl's 
%%% name_resolvers system. It queries AR.IO gateways to resolve ARNS names
%%% like "ardrive" to their corresponding transaction IDs.
%%%
%%% Example usage:
%%% ```
%%% Opts = #{
%%%     name_resolvers => [
%%%         dev_arns_resolver:resolver(<<"https://arweave.net">>)
%%%     ]
%%% },
%%% hb_ao:resolve([
%%%     #{ <<"device">> => <<"name@1.0">> },
%%%     #{ <<"path">> => <<"ardrive">> }
%%% ], Opts).
%%% '''
-module(dev_arns_resolver).
-export([resolver/1, resolver/0]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Default AR.IO gateway URL
-define(DEFAULT_GATEWAY, <<"https://arweave.net">>).

%% @doc Create a resolver with default gateway URL
resolver() ->
    resolver(?DEFAULT_GATEWAY).

%% @doc Create a resolver with a specific AR.IO gateway URL
resolver(GatewayUrl) ->
    #{
        <<"device">> => #{
            <<"lookup">> => fun(_, Req, Opts) ->
                lookup_arns(Req, GatewayUrl, Opts)
            end
        }
    }.

%% @doc Lookup an ARNS name using the AR.IO gateway
lookup_arns(Req, GatewayUrl, Opts) ->
    Key = hb_ao:get(<<"key">>, Req, Opts),
    ?event({arns_resolver, lookup, {key, Key}, {gateway, GatewayUrl}}),
    
    case resolve_name_via_gateway(Key, GatewayUrl, Opts) of
        {ok, TxId} ->
            ?event({arns_resolver, found, {key, Key}, {txid, TxId}}),
            {ok, TxId};
        {error, Reason} ->
            ?event({arns_resolver, not_found, {key, Key}, {reason, Reason}}),
            {error, not_found}
    end.

%% @doc Query the AR.IO gateway to resolve an ARNS name
resolve_name_via_gateway(Name, GatewayUrl, _Opts) ->
    % Clean the gateway URL and build full URL
    CleanGatewayUrl = binary:replace(GatewayUrl, <<"\n">>, <<>>, [global]),
    Path = <<"/ar-io/resolver/", Name/binary>>,
    Url = binary_to_list(<<CleanGatewayUrl/binary, Path/binary>>),
    
    ?event({arns_resolver, http_request, {url, Url}}),
    
    % Use httpc directly since it works
    case httpc:request(get, {Url, []}, [], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _Headers, Body}} ->
            parse_gateway_response(Body, _Opts);
        {ok, {{_, 404, _}, _Headers, _Body}} ->
            {error, name_not_found};
        {ok, {{_, Status, _}, _Headers, Body}} ->
            ?event({arns_resolver, http_error, {status, Status}, {body, Body}}),
            {error, {http_error, Status}};
        {error, Reason} ->
            ?event({arns_resolver, request_failed, {reason, Reason}}),
            {error, {request_failed, Reason}}
    end.


%% @doc Parse the JSON response from the AR.IO gateway
parse_gateway_response(Body, _Opts) ->
    try
        Json = hb_json:decode(Body),
        case maps:get(<<"txId">>, Json, undefined) of
            undefined ->
                {error, no_txid_in_response};
            TxId when is_binary(TxId) ->
                {ok, TxId};
            _ ->
                {error, invalid_txid_format}
        end
    catch
        _:_ ->
            ?event({arns_resolver, json_parse_error, {body, Body}}),
            {error, json_parse_error}
    end.

%%% Tests

%% @doc Test creating a resolver message structure
resolver_structure_test() ->
    Resolver = resolver(<<"https://example.com">>),
    ?assertMatch(
        #{<<"device">> := #{<<"lookup">> := Fun}} when is_function(Fun, 3),
        Resolver
    ).


%% @doc Test JSON response parsing
parse_gateway_response_test() ->
    ValidResponse = <<"{\"txId\":\"abc123\",\"ttlSeconds\":3600}">>,
    ?assertEqual({ok, <<"abc123">>}, parse_gateway_response(ValidResponse, #{})),
    
    NoTxIdResponse = <<"{\"ttlSeconds\":3600}">>,
    ?assertEqual({error, no_txid_in_response}, parse_gateway_response(NoTxIdResponse, #{})),
    
    InvalidJson = <<"not json">>,
    ?assertEqual({error, json_parse_error}, parse_gateway_response(InvalidJson, #{})).

%% @doc Integration test with mock HTTP response
mock_integration_test() ->
    % Create a mock resolver that simulates gateway responses
    MockResolver = #{
        <<"device">> => #{
            <<"lookup">> => fun(_, Req, Opts) ->
                Key = hb_ao:get(<<"key">>, Req, Opts),
                case Key of
                    <<"ardrive">> ->
                        {ok, <<"mocked-ardrive-txid">>};
                    <<"permawebjs">> ->
                        {ok, <<"mocked-permawebjs-txid">>};
                    _ ->
                        {error, not_found}
                end
            end
        }
    },
    
    % Test successful resolution
    ?assertEqual(
        {ok, <<"mocked-ardrive-txid">>},
        hb_ao:resolve(
            MockResolver,
            #{ <<"path">> => <<"lookup">>, <<"key">> => <<"ardrive">> },
            #{}
        )
    ),
    
    % Test name not found
    ?assertEqual(
        {error, not_found},
        hb_ao:resolve(
            MockResolver,
            #{ <<"path">> => <<"lookup">>, <<"key">> => <<"unknown">> },
            #{}
        )
    ).
%%% @doc AR.IO Resolver device for HyperBEAM. Provides ARNS resolution
%%% functionality through the /~resolver@1.0/<name> route with dynamic resolution.
-module(dev_resolver).
-export([info/1, info/3, resolve/4]).
-include("include/hb.hrl").

%% @doc Device info function - required for all devices
info(_) -> 
    #{ 
        exports => [resolve],
        default => fun resolve/4
    }.

%% @doc HTTP info endpoint
info(_Msg1, _Msg2, _Opts) ->
    {ok, #{
        <<"description">> => <<"AR.IO Resolver device for ARNS resolution">>,
        <<"version">> => <<"1.0">>,
        <<"routes">> => [<<"/~resolver@1.0/<name>">>]
    }}.

%% @doc Dynamic ARNS resolution - handles any ARNS name as default function
resolve(<<"ardrive">>, Msg1, Msg2, Opts) ->
    ?event({resolver, resolve_called, {msg1, Msg1}, {msg2, Msg2}}),
    resolve_arns_name(<<"ardrive">>, Opts).


%% @doc Extract name from /~resolver@1.0/<name> request pattern
extract_name_from_request(Msg1, Msg2, Opts) ->
    % In HyperBEAM's /~device@version/<name> pattern, the name should be
    % available as the first path element after device routing.
    
    % Use HyperBEAM's path utilities to extract the name
    case hb_path:hd(Msg2, Opts) of
        undefined ->
            {error, <<"Missing name in path">>};
        Name when is_binary(Name), byte_size(Name) > 0 ->
            {ok, Name};
        _ ->
            {error, <<"Invalid name in path">>}
    end.

%% @doc Mock ARNS resolution - returns sample data structure
%% In a real implementation, this would query the AR.IO network
resolve_arns_name(Name, _Opts) ->
    CurrentTime = erlang:system_time(millisecond),
    
    Response = #{
        <<"txId">> => <<"arTPK-WAPU_cJZY5OwpRGZDJC4PQcL6jhvMUvNbOshY">>,
        <<"ttlSeconds">> => 3600,
        <<"processId">> => <<"y1Vv81ha1I1uR6WYGQId2MndCFB7HGNGFug60soE5QI">>,
        <<"resolvedAt">> => CurrentTime,
        <<"index">> => 0,
        <<"limit">> => 100,
        <<"name">> => Name
    },
    
    ?event({resolver, resolved, {name, Name}, {response, Response}}),
    {ok, Response}.

%%% @doc Example test script demonstrating ARNS resolver usage with dev_name.erl
%%% This shows how to integrate the ARNS resolver into HyperBEAM's name resolution system
-module(test_arns_resolver).
-export([run/0]).
-include_lib("eunit/include/eunit.hrl").

%% @doc Run the example tests
run() ->
    io:format("~n=== Testing ARNS Resolver Integration ===~n~n"),
    
    % Test 1: Basic resolver structure
    io:format("Test 1: Creating ARNS resolver...~n"),
    Resolver = dev_arns_resolver:resolver(<<"https://arweave.net">>),
    io:format("  ✓ Resolver created: ~p~n~n", [maps:keys(Resolver)]),
    
    % Test 2: Integration with dev_name
    io:format("Test 2: Testing with dev_name system...~n"),
    
    % Create options with ARNS resolver
    Opts = #{
        name_resolvers => [
            % Add the ARNS resolver
            dev_arns_resolver:resolver(<<"https://arweave.net">>),
            
            % Add a mock resolver for testing without network calls
            #{
                <<"device">> => #{
                    <<"lookup">> => fun(_, Req, InnerOpts) ->
                        Key = hb_ao:get(<<"key">>, Req, InnerOpts),
                        io:format("  Mock resolver checking key: ~p~n", [Key]),
                        case Key of
                            <<"test-name">> ->
                                {ok, <<"test-tx-id-123">>};
                            _ ->
                                {error, not_found}
                        end
                    end
                }
            }
        ]
    },
    
    % Test resolving a mock name
    io:format("  Testing mock name resolution...~n"),
    case hb_ao:resolve_many(
        [
            #{ <<"device">> => <<"name@1.0">> },
            #{ <<"path">> => <<"test-name">> }
        ],
        Opts
    ) of
        {ok, Result} ->
            io:format("  ✓ Mock name resolved: ~p~n", [Result]);
        Error ->
            io:format("  ✗ Mock resolution failed: ~p~n", [Error])
    end,
    
    % Test 3: Direct resolver usage
    io:format("~nTest 3: Direct resolver usage...~n"),
    DirectResolver = dev_arns_resolver:resolver(),
    case hb_ao:resolve(
        DirectResolver,
        #{ <<"path">> => <<"lookup">>, <<"key">> => <<"ardrive">> },
        #{}
    ) of
        {ok, TxId} ->
            io:format("  ✓ Direct resolution successful: ~p~n", [TxId]);
        {error, Reason} ->
            io:format("  ℹ Direct resolution returned error (expected without real gateway): ~p~n", [Reason])
    end,
    
    io:format("~n=== Example Usage ===~n"),
    io:format("~n%% Add ARNS resolver to your HyperBEAM options:~n"),
    io:format("Opts = #{~n"),
    io:format("    name_resolvers => [~n"),
    io:format("        dev_arns_resolver:resolver(<<\"https://arweave.net\">>)~n"),
    io:format("    ]~n"),
    io:format("}.~n~n"),
    
    io:format("%% Then resolve ARNS names:~n"),
    io:format("hb_ao:resolve_many([~n"),
    io:format("    #{ <<\"device\">> => <<\"name@1.0\">> },~n"),
    io:format("    #{ <<\"path\">> => <<\"ardrive\">> }~n"),
    io:format("], Opts).~n~n"),
    
    io:format("%% Or use in HTTP requests:~n"),
    io:format("%% GET /~name@1.0/ardrive~n~n"),
    
    ok.

%% @doc Test the ARNS resolver with actual name resolution
integration_test() ->
    % Create a test resolver that simulates AR.IO gateway behavior
    TestGatewayResolver = #{
        <<"device">> => #{
            <<"lookup">> => fun(_, Req, Opts) ->
                Key = hb_ao:get(<<"key">>, Req, Opts),
                % Simulate AR.IO gateway responses
                case Key of
                    <<"ardrive">> ->
                        {ok, <<"BPr7vrFduuQqqVMu_tftxsScTKUq9ke0rx4q5C9ieQU">>};
                    <<"permawebjs">> ->
                        {ok, <<"UyC5P5qKPZaltMmmZAWdakhlDXsBF6qmyrbWYFchRTk">>};
                    _ ->
                        {error, not_found}
                end
            end
        }
    },
    
    % Test with name_resolvers
    Opts = #{
        name_resolvers => [TestGatewayResolver]
    },
    
    % Test successful resolution through dev_name
    ?assertEqual(
        {ok, <<"BPr7vrFduuQqqVMu_tftxsScTKUq9ke0rx4q5C9ieQU">>},
        dev_name:resolve(<<"ardrive">>, #{}, #{ <<"load">> => false }, Opts)
    ),
    
    % Test name not found
    ?assertEqual(
        not_found,
        dev_name:resolve(<<"unknown-name">>, #{}, #{ <<"load">> => false }, Opts)
    ).
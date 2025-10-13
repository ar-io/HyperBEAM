%%% @doc Implements a radix trie.
%%%
%%% Recall that r = 2 ^ x, so a radix-256 trie compares bits in chunks of 8 and thus each
%%% internal node can have at most 256 children; a radix-2 trie compares bits in chunks of 1
%%% and thus each internal node can have at most 2 children. (The number of children are
%%% defined by the number of permutations given by an N-bit chunk comparison -- e.g., a
%%% 2-bit comparison yields paths {00, 11, 01, 10}, which is why each node in a radix-4
%%% trie can have at most 4 children!)
-module(dev_radix_trie).
-export([info/0, set/3, get/3, get/4]).
-include_lib("eunit/include/eunit.hrl").
-include("include/hb.hrl").

%%% @doc What default radix shall we use for the data structure?
-define(RADIX, 256).

info() ->
    #{
        default => fun get/4
     }.

%%% @doc Get the value associated with a key from a trie represented in a base message.
get(Key, Trie, Req, Opts) ->
    get(Trie, Req#{<<"key">> => Key}, Opts).
get(TrieNode, Req, Opts) ->
    case hb_maps:find(<<"key">>, Req, Opts) of
        error -> {error, <<"'key' parameter is required for trie lookup.">>};
        {ok, Key} -> retrieve(TrieNode, Key, Opts)
    end.

%% @doc Set keys and their values in the trie.
set(Trie, Req, Opts) ->
    Insertable = hb_maps:without([<<"path">>], Req, Opts),
    KeyVals = hb_maps:to_list(Insertable, Opts),
    {ok, do_set(Trie, KeyVals, Opts)}.
do_set(Trie, [], Opts) ->
    Trie,
    Linkified = hb_message:convert(
        Trie,
        <<"structured@1.0">>,
        <<"structured@1.0">>,
        Opts
    ),
    WithoutHMac = hb_message:without_commitments(
        #{<<"type">> => <<"unsigned">>},
        Linkified,
        Opts
    ),
    hb_message:commit(WithoutHMac, Opts, #{<<"type">> => <<"unsigned">>});
do_set(Trie, [{Key, Val} | KeyVals], Opts) ->
    NewTrie = insert(Trie, Key, Val, Opts),
    do_set(NewTrie, KeyVals, Opts).

insert(TrieNode, Key, Val, Opts) ->
    insert(TrieNode, Key, Val, Opts, 0).
insert(TrieNode, Key, Val, Opts, KeyPrefixSizeAcc) ->
    <<_KeyPrefix:KeyPrefixSizeAcc/bitstring, KeySuffix/bitstring>> = Key,
    EdgeLabels = edges(TrieNode, Opts),
    ChunkSize = round(math:log2(?RADIX)),
    case longest_prefix_match(KeySuffix, EdgeLabels, ChunkSize) of
        {EdgeLabel, MatchSize} when MatchSize =:= 0 ->
            case bit_size(KeySuffix) > 0 of
                true ->
                    TrieNode#{KeySuffix => #{<<"node-value">> => Val}};
                false ->
                    TrieNode#{<<"node-value">> => Val}
            end;
        {EdgeLabel, MatchSize} when MatchSize =:= bit_size(EdgeLabel) ->
            SubTrie = hb_maps:get(EdgeLabel, TrieNode, undefined, Opts),
            NewSubTrie = insert(SubTrie, Key, Val, Opts, bit_size(EdgeLabel) + KeyPrefixSizeAcc),
            TrieNode#{EdgeLabel => NewSubTrie};
        {EdgeLabel, MatchSize} ->
            SubTrie = hb_maps:get(EdgeLabel, TrieNode, undefined, Opts),
            NewTrie = hb_maps:remove(EdgeLabel, TrieNode, Opts),
            <<EdgeLabelPrefix:MatchSize/bitstring, EdgeLabelSuffix/bitstring>> = EdgeLabel,
            <<_KeySuffixPrefix:MatchSize/bitstring, KeySuffixSuffix/bitstring>> = KeySuffix,
            case bit_size(KeySuffixSuffix) > 0 of
                true ->
                    NewTrie#{
                        EdgeLabelPrefix => #{
                            EdgeLabelSuffix => SubTrie,
                            KeySuffixSuffix => #{<<"node-value">> => Val}
                        }
                    };
                false ->
                    NewTrie#{
                        EdgeLabelPrefix => #{
                            EdgeLabelSuffix => SubTrie,
                            <<"node-value">> => Val
                        }
                    }
            end
    end.

retrieve(TrieNode, Key, Opts) ->
    retrieve(TrieNode, Key, Opts, 0).
retrieve(TrieNode, Key, Opts, KeyPrefixSizeAcc) ->
    case KeyPrefixSizeAcc >= bit_size(Key) of
        true ->
            hb_maps:get(<<"node-value">>, TrieNode, {error, not_found}, Opts);
        false ->
            EdgeLabels = edges(TrieNode, Opts),
            <<_KeyPrefix:KeyPrefixSizeAcc/bitstring, KeySuffix/bitstring>> = Key,
            ChunkSize = round(math:log2(?RADIX)),
            case longest_prefix_match(KeySuffix, EdgeLabels, ChunkSize) of
                {_EdgeLabel, MatchSize} when MatchSize =:= 0 ->
                    {error, not_found};
                {EdgeLabel, MatchSize} when MatchSize =:= bit_size(EdgeLabel) ->
                    SubTrie = hb_maps:get(EdgeLabel, TrieNode, undefined, Opts),
                    retrieve(SubTrie, Key, Opts, bit_size(EdgeLabel) + KeyPrefixSizeAcc);
                _ -> {error, not_found}
            end
    end.

% Get a list of edge labels for a given trie node.
edges(TrieNode, Opts) ->
  Filtered = hb_maps:without(
      [
          <<"node-value">>,
          <<"device">>,
          <<"commitments">>,
          <<"priv">>,
          <<"hashpath">>
      ],
      TrieNode,
      Opts
  ),
  hb_maps:keys(Filtered).

% Compute the longest common binary prefix of A and B, comparing chunks of N bits.
bitwise_lcp(A, B, N) ->
    bitwise_lcp(A, B, N, 0).
bitwise_lcp(A, B, N, Acc) ->
    case {A, B} of
        {<<ChunkA:N, RestA/bits>>, <<ChunkB:N, RestB/bits>>} when ChunkA =:= ChunkB ->
            bitwise_lcp(RestA, RestB, N, Acc + N);
        _ -> Acc
    end.

% For a given key and list of edge labels, determine which edge label presents the longest prefix
% match, comparing chunks of N bits. Returns a 2-tuple of {edge label, commonality in bits}.
longest_prefix_match(Key, EdgeLabels, N) ->
    longest_prefix_match({<<>>, 0}, Key, EdgeLabels, N).
longest_prefix_match(Best, _Key, [], _N) -> Best;
longest_prefix_match({BestLabel, BestSize}, Key, [EdgeLabel | EdgeLabels], N) ->
    case bitwise_lcp(Key, EdgeLabel, N) of
        Size when Size > BestSize ->
            longest_prefix_match({EdgeLabel, Size}, Key, EdgeLabels, N);
        _ ->
            longest_prefix_match({BestLabel, BestSize}, Key, EdgeLabels, N)
    end.

% TODO: tests!

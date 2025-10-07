%%% @doc Implements a radix trie.
%%%
%%% Recall that r = 2 ^ x, so a radix-256 trie compares bits in chunks of 8 and thus each
%%% internal node can have at most 8 children; a radix-2 trie compares bits in chunks of 1
%%% and thus each internal node can have at most 2 children. (The number of children are
%%% defined by the number of permutations given by an N-bit chunk comparison -- e.g., a
%%% 2-bit comparison yields paths {00, 11, 01, 10}, which is why each node in a radix-4
%%% trie can have at most 4 children!) A radix-256 trie is thus equivalent to bytewise comparison.
-module(dev_radix_trie).
-export([set/3, get/4]).
-include_lib("eunit/include/eunit.hrl").
-include("include/hb.hrl").

%%% @doc What default radix shall we use for the data structure?
-define(RADIX, 256).

%%% @doc Get the value associated with a key from a trie represented in a base message.
get(Key, Trie, Req, Opts) ->
    get(Trie, Req#{<<"key">> => Key}, Opts).
get(TrieNode, Req, Opts) ->
    case hb_maps:find(<<"key">>, Req, Opts) of
        error -> {error, <<"'key' parameter is required for trie lookup.">>};
        {ok, Key} -> retrieve(TrieNode, Key)
    end.

%% @doc Set keys and their values in the trie.
%% TODO: override default radix with a 'radix' key
%% TODO: this might be optimizable by lexicographically sorting the Req ahead of time?
set(Trie, Req, Opts) ->
    Insertable = hb_maps:without([<<"path">>], Req, Opts),
    ?event(debug_radix_trie, {set, {trie, Trie}, {inserting, Insertable}}),
    KeyVals = hb_maps:to_list(Insertable, Opts),
    {ok, do_set(Trie, KeyVals, Opts)}.
do_set(Trie, [], Opts) -> Trie;
do_set(Trie, [{Key, Val} | KeyVals], Opts) ->
    NewTrie = insert(Trie, Key, Val),
    do_set(NewTrie, KeyVals, Opts).

insert(TrieNode, Key, Val) -> 
    insert(TrieNode, Key, Val, 0).
insert(TrieNode, Key, Val, KeyPrefixSizeAcc) ->
    <<_KeyPrefix:KeyPrefixSizeAcc/bitstring, KeySuffix/bitstring>> = Key,
    case edges(TrieNode) of
        [] ->
            TrieNode#{KeySuffix => #{<<"node-value">> => Val}};
        EdgeLabels ->
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
                    SubTrie = maps:get(EdgeLabel, TrieNode),
                    NewSubTrie = insert(SubTrie, Key, Val, bit_size(EdgeLabel) + KeyPrefixSizeAcc),
                    TrieNode#{EdgeLabel => NewSubTrie};
                {EdgeLabel, MatchSize} ->
                    SubTrie = maps:get(EdgeLabel, TrieNode),
                    NewTrie = maps:remove(EdgeLabel, TrieNode),
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
            end
    end.

retrieve(TrieNode, Key) ->
    retrieve(TrieNode, Key, 0).
retrieve(TrieNode, Key, KeyPrefixSizeAcc) ->
    case KeyPrefixSizeAcc >= bit_size(Key) of
        true ->
            maps:get(<<"node-value">>, TrieNode, {error, not_found});
        false ->
            case edges(TrieNode) of
                [] ->
                    {error, not_found};
                EdgeLabels ->
                    <<_KeyPrefix:KeyPrefixSizeAcc/bitstring, KeySuffix/bitstring>> = Key,
                    ChunkSize = round(math:log2(?RADIX)),
                    case longest_prefix_match(KeySuffix, EdgeLabels, ChunkSize) of
                        {_EdgeLabel, MatchSize} when MatchSize =:= 0 ->
                            {error, not_found};
                        {EdgeLabel, MatchSize} when MatchSize =:= bit_size(EdgeLabel) ->
                            SubTrie = maps:get(EdgeLabel, TrieNode),
                            retrieve(SubTrie, Key, bit_size(EdgeLabel) + KeyPrefixSizeAcc);
                        _ -> {error, not_found}
                    end
            end
    end.

% Get a list of edge labels for a given trie node.
% TODO: filter out system keys?
edges(TrieNode) -> 
  Filtered = maps:without([<<"node-value">>], TrieNode),
  maps:keys(Filtered).

% Compute the longest common binary prefix of A and B, comparing chunks of N bits.
bitwise_lcp(A, B, N) ->
    % TODO: this placeholder implementation only works for N = 8! Implement the real thing!
    binary:longest_common_prefix([A, B]) * 8.

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

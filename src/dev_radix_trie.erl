%%% @doc Implements a radix trie.
%%%
%%% This implementation features an optimization which reduces the total number of messages
%%% required to represent the trie by collapsing leaf nodes into their parent messages --
%%% i.e., "implicit" leaf nodes. This requires some special case handling during insertion
%%% and retrieval, but it can reduce the total number of messages by more than half.
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

%%% @doc What default radix shall we use for the data structure? Setting this to a value
%%% other than 256 will result in undefined behavior. Sub-byte chunking for divisors of 8
%%% (radix-2, radix-4, radix-16) seems to work, but cannot be properly normalized.
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
        % NO MATCH: This internal node has no traversible children, because its
        % edge labels do not match any portion of what remains to be matched of our
        % key. If we've matched the entire length of our key on our way here, then it
        % seems we're trying to insert a key which corresponds to the terminal value kept
        % at this very internal node, so we insert it here. If not, we add an edge to a
        % new leaf node that's labeled with the remaining key suffix, and we insert our
        % value into that leaf node. Note the implicit leaf node! In a world with explicit
        % leaf nodes, it would look like: TrieNode#{KeySuffix => #{<<"node-value">> => Val}
        {EdgeLabel, MatchSize} when MatchSize =:= 0 ->
            case bit_size(KeySuffix) > 0 of
                true ->
                    % Implicit leaf node creation!
                    TrieNode#{KeySuffix => Val};
                false ->
                    TrieNode#{<<"node-value">> => Val}
            end;
        % FULL MATCH: There is a child of this node with an edge label that completely
        % matches *some portion* of what remains to be matched in our key. If the child
        % is a normal node, this is the straightforward recursive case -- we simply traverse
        % to that child and continue. But if the child is an implicit leaf node, we've
        % reached a base case: if the edge label to the implicit leaf node is exactly
        % the same size as the remaining key suffix, then we've effectively discovered
        % that the key we're trying to insert already exists, and its value is kept
        % in an implicit leaf node, so we simply update it. If the edge label *isn't*
        % the same size, we must transform the implicit leaf node into an internal node
        % which marks the terminal value for its key, and add to it an edge
        % representing the remaining key suffix which maps to a new implicit leaf node.
        {EdgeLabel, MatchSize} when MatchSize =:= bit_size(EdgeLabel) ->
            SubTrie = hb_maps:get(EdgeLabel, TrieNode, undefined, Opts),
            case is_map(SubTrie) of
                false ->
                    if
                        bit_size(KeySuffix) =:= bit_size(EdgeLabel) ->
                            TrieNode#{EdgeLabel => Val};
                        true ->
                            <<_KeySuffixPrefix:MatchSize/bitstring, KeySuffixSuffix/bitstring>> = KeySuffix,
                            TrieNode#{EdgeLabel => #{<<"node-value">> => SubTrie, KeySuffixSuffix => Val}}
                    end;
                true ->
                    NewSubTrie = insert(SubTrie, Key, Val, Opts, bit_size(EdgeLabel) + KeyPrefixSizeAcc),
                    TrieNode#{EdgeLabel => NewSubTrie}
            end;
        % PARTIAL MATCH: There is a child of this node with an edge label that partially
        % matches *some portion* of what remains to be matched in our key. This is the
        % node splitting case. We detach the subtrie rooted at the child, transform its
        % dangling edge label into the common portion of the edge label and what remains
        % to be matched in our key, and reattach the new subtrie under a new child.
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
                            % Implicit leaf node!
                            KeySuffixSuffix => Val
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
                    % Special case handling for implicit leaf nodes: if the
                    % child node corresponding to the edge label is not a map, and
                    % the edge label is *precisely* the same size as the remaining
                    % key suffix, then SubTrie is an implicit leaf node -- i.e.,
                    % it's the value associated with the key we're searching for.
                    % When the edge label is not the same size as the remaining key
                    % suffix, that indicates a search for a nonexistent key with
                    % a partial prefix match on an implicit leaf node -- i.e.,
                    % if "car" is an implicit leaf node but we searched for "card".
                    case is_map(SubTrie) of
                        false ->
                            if
                                bit_size(KeySuffix) =:= bit_size(EdgeLabel) -> SubTrie;
                                true -> {error, not_found}
                            end;
                        true ->
                            retrieve(SubTrie, Key, Opts, bit_size(EdgeLabel) + KeyPrefixSizeAcc)
                    end;
                _ -> {error, not_found}
            end
    end.

% Get a list of edge labels for a given trie node.
edges(TrieNode, Opts) when not is_map(TrieNode) -> [];
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

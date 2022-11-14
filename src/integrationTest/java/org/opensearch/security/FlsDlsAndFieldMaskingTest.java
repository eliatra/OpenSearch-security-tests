/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.metrics.ParsedAvg;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.*;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryByIdsRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsExactlyIndices;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsFieldWithNameAndType;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.numberOfFieldsIsEqualTo;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containDocument;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentContainsExactlyFieldsWithNames;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.isSuccessfulMultiGetResponse;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.numberOfGetItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.isSuccessfulMultiSearchResponse;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.numberOfSearchItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentWithId;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsDocumentsContainExactlyFieldsWithNames;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FlsDlsAndFieldMaskingTest {

    static final String FIRST_INDEX_ID_SONG_1 = "INDEX_1_S1";
    static final String FIRST_INDEX_ID_SONG_2 = "INDEX_1_S2";
    static final String FIRST_INDEX_ID_SONG_3 = "INDEX_1_S3";
    static final String FIRST_INDEX_ID_SONG_4 = "INDEX_1_S4";
    static final String SECOND_INDEX_ID_SONG_1 = "INDEX_2_S1";
    static final String SECOND_INDEX_ID_SONG_2 = "INDEX_2_S2";
    static final String SECOND_INDEX_ID_SONG_3 = "INDEX_2_S3";
    static final String SECOND_INDEX_ID_SONG_4 = "INDEX_2_S4";

    static final String INDEX_NAME_SUFFIX = "-test-index";
    static final String FIRST_INDEX_NAME = "first".concat(INDEX_NAME_SUFFIX);
    static final String SECOND_INDEX_NAME = "second".concat(INDEX_NAME_SUFFIX);
    static final String FIRST_INDEX_ALIAS = FIRST_INDEX_NAME.concat("-alias");
    static final String SECOND_INDEX_ALIAS = SECOND_INDEX_NAME.concat("-alias");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE = FIRST_INDEX_NAME.concat("-filtered-by-next-song-title");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_TWINS_ARTIST = FIRST_INDEX_NAME.concat("-filtered-by-twins-artist");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_FIRST_ARTIST = FIRST_INDEX_NAME.concat("-filtered-by-first-artist");
    static final String ALL_INDICES_ALIAS = "_all";

    static final String MASK_VALUE = "*";


    /**
     * User who is allowed to see the title and stars fields on all indices
     */
    static final TestSecurityConfig.User ALL_INDICES_TITLE_STARS_READER = new TestSecurityConfig.User("title_stars_reader")
            .roles(
                    new TestSecurityConfig.Role("title_stars_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(FIELD_TITLE, FIELD_STARS)
                            .on("*")
            );

    /**
     * User who is allowed to see the title, artist and lyrics fields on index {@link #FIRST_INDEX_NAME}, and
     * the artist field on index {@link #SECOND_INDEX_NAME}
     */
    static final TestSecurityConfig.User TITLE_ARTIST_LYRICS_READER_USER = new TestSecurityConfig.User("title_artist_lyrics_reader")
            .roles(
                    new TestSecurityConfig.Role("title_artist_lyrics_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(
                                    FIELD_TITLE,
                                    FIELD_ARTIST.substring(0,3).concat("*"),
                                    "*".concat(FIELD_LYRICS.substring(FIELD_LYRICS.length() - 3))
                            )
                            .on(FIRST_INDEX_NAME),
                    new TestSecurityConfig.Role("artist_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(FIELD_ARTIST)
                            .on(SECOND_INDEX_NAME)
            );

    /**
     * User who is allowed to see the title field on index {@link #FIRST_INDEX_NAME}
     */
    static final TestSecurityConfig.User TITLE_READER = new TestSecurityConfig.User("title_reader")
            .roles(
                    new TestSecurityConfig.Role("title_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(
                                    "~".concat(FIELD_ARTIST),
                                    "~".concat(FIELD_LYRICS.substring(0,3).concat("*")),
                                    "~*".concat(FIELD_STARS.substring(FIELD_STARS.length() - 3)),
                                    "~".concat(FIELD_GENRE)
                            )
                            .on(FIRST_INDEX_NAME)
            );

    /**
     * User who is allowed to see all fields on all indices. Values of the title and artist fields should be masked.
     */
    static final TestSecurityConfig.User ALL_INDICES_MASKED_TITLE_ARTIST_READER = new TestSecurityConfig.User("masked_artist_title_reader")
            .roles(
                    new TestSecurityConfig.Role("masked_artist_title_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .maskedFields(
                                    FIELD_TITLE.concat("::/(?<=.{1})./::").concat(MASK_VALUE),
                                    FIELD_ARTIST.concat("::/(?<=.{1})./::").concat(MASK_VALUE)
                            )
                            .on("*")
            );

    /**
     * User who is allowed to see all fields on indices {@link #FIRST_INDEX_NAME} and {@link #SECOND_INDEX_NAME}.
     * <ul>
     *     <li>values of the artist and lyrics fields should be masked on index {@link #FIRST_INDEX_NAME}</li>
     *     <li>values of the lyrics field should be masked on index {@link #SECOND_INDEX_NAME}</li>
     * </ul>
     */
    static final TestSecurityConfig.User MASKED_ARTIST_LYRICS_READER = new TestSecurityConfig.User("masked_title_artist_lyrics_reader")
            .roles(
                    new TestSecurityConfig.Role("masked_title_artist_lyrics_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .maskedFields(
                                    FIELD_ARTIST.concat("::/(?<=.{1})./::").concat(MASK_VALUE),
                                    FIELD_LYRICS.concat("::/(?<=.{1})./::").concat(MASK_VALUE)
                            )
                            .on(FIRST_INDEX_NAME),
                    new TestSecurityConfig.Role("masked_lyrics_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .maskedFields(FIELD_LYRICS.concat("::/(?<=.{1})./::").concat(MASK_VALUE))
                            .on(SECOND_INDEX_NAME)
            );

    /**
     * Function that converts field value to value masked with {@link #MASK_VALUE}
     */
    static final Function<String, String> VALUE_TO_MASKED_VALUE = value -> value.substring(0, 1)
            .concat(MASK_VALUE.repeat(value.length() - 1));

    /**
     * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_STRING}.
     */
    static final TestSecurityConfig.User ALL_INDICES_STRING_ARTIST_READER = new TestSecurityConfig.User("string_artist_reader")
            .roles(
                    new TestSecurityConfig.Role("string_artist_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_STRING))
                            .on("*")
            );

    /**
     * User who is allowed to see documents on index:
     * <ul>
     *     <li>{@link #FIRST_INDEX_NAME} where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_TWINS}</li>
     *     <li>{@link #SECOND_INDEX_NAME} where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_FIRST}</li>
     * </ul>
     */
    static final TestSecurityConfig.User TWINS_FIRST_ARTIST_READER = new TestSecurityConfig.User("twins_first_artist_reader")
            .roles(
                    new TestSecurityConfig.Role("twins_artist_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_TWINS))
                            .on(FIRST_INDEX_NAME),
                    new TestSecurityConfig.Role("first_artist_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_FIRST))
                            .on(SECOND_INDEX_NAME)
            );

    /**
     * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_STARS} is less than zero.
     */
    static final TestSecurityConfig.User ALL_INDICES_STARS_LESS_THAN_ZERO_READER = new TestSecurityConfig.User("stars_less_than_zero_reader")
            .roles(
                    new TestSecurityConfig.Role("stars_less_than_zero_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .dls(String.format("{\"range\":{\"%s\":{\"lt\":%d}}}", FIELD_STARS, 0))
                            .on("*")
            );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder()
            .clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS).anonymousAuth(false)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(
                    ALL_INDICES_TITLE_STARS_READER, TITLE_ARTIST_LYRICS_READER_USER, TITLE_READER,
                    ALL_INDICES_MASKED_TITLE_ARTIST_READER, MASKED_ARTIST_LYRICS_READER,
                    ALL_INDICES_STRING_ARTIST_READER, ALL_INDICES_STARS_LESS_THAN_ZERO_READER, TWINS_FIRST_ARTIST_READER
            )
            .build();

    /**
     * Function that returns id assigned to song with title equal to given title or throws {@link RuntimeException}
     * when no song matches.
     */
    static final BiFunction<Map<String, Song>, String, String> FIND_ID_OF_SONG_WITH_TITLE = (map, title) -> map.entrySet()
            .stream().filter(entry -> title.equals(entry.getValue().getTitle()))
            .findAny()
            .map(Map.Entry::getKey)
            .orElseThrow(() -> new RuntimeException("Cannot find id of song with title: " + title));

    /**
     * Function that returns id assigned to song with artist equal to given artist or throws {@link RuntimeException}
     * when no song matches.
     */
    static final BiFunction<Map<String, Song>, String, String> FIND_ID_OF_SONG_WITH_ARTIST = (map, artist) -> map.entrySet()
            .stream().filter(entry -> artist.equals(entry.getValue().getArtist()))
            .findAny()
            .map(Map.Entry::getKey)
            .orElseThrow(() -> new RuntimeException("Cannot find id of song with artist: " + artist));

    static final TreeMap<String, Song> FIRST_INDEX_SONGS_BY_ID = new TreeMap<>() {{
        put(FIRST_INDEX_ID_SONG_1, SONGS[0]);
        put(FIRST_INDEX_ID_SONG_2, SONGS[1]);
        put(FIRST_INDEX_ID_SONG_3, SONGS[2]);
        put(FIRST_INDEX_ID_SONG_4, SONGS[3]);
    }};

    static final TreeMap<String, Song> SECOND_INDEX_SONGS_BY_ID = new TreeMap<>() {{
        put(SECOND_INDEX_ID_SONG_1, SONGS[3]);
        put(SECOND_INDEX_ID_SONG_2, SONGS[2]);
        put(SECOND_INDEX_ID_SONG_3, SONGS[1]);
        put(SECOND_INDEX_ID_SONG_4, SONGS[0]);
    }};

    @BeforeClass
    public static void createTestData() {
        try(Client client = cluster.getInternalNodeClient()){
            FIRST_INDEX_SONGS_BY_ID.forEach((id, song) -> {
                client.prepareIndex(FIRST_INDEX_NAME).setId(id).setRefreshPolicy(IMMEDIATE).setSource(song.asMap()).get();
            });

            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .indices(FIRST_INDEX_NAME)
                    .alias(FIRST_INDEX_ALIAS)
            )).actionGet();
            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .index(FIRST_INDEX_NAME)
                    .alias(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE)
                    .filter(QueryBuilders.queryStringQuery(QUERY_TITLE_NEXT_SONG))
            )).actionGet();
            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .index(FIRST_INDEX_NAME)
                    .alias(FIRST_INDEX_ALIAS_FILTERED_BY_TWINS_ARTIST)
                    .filter(QueryBuilders.queryStringQuery(String.format("%s:%s", FIELD_ARTIST, ARTIST_TWINS)))
            )).actionGet();
            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .index(FIRST_INDEX_NAME)
                    .alias(FIRST_INDEX_ALIAS_FILTERED_BY_FIRST_ARTIST)
                    .filter(QueryBuilders.queryStringQuery(String.format("%s:%s", FIELD_ARTIST, ARTIST_FIRST)))
            )).actionGet();

            SECOND_INDEX_SONGS_BY_ID.forEach((id, song) -> {
                client.prepareIndex(SECOND_INDEX_NAME).setId(id).setRefreshPolicy(IMMEDIATE).setSource(song.asMap()).get();
            });
            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .indices(SECOND_INDEX_NAME)
                    .alias(SECOND_INDEX_ALIAS)
            )).actionGet();
        }
    }

    @Test
    public void searchForDocuments() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_1;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest =  queryByIdsRequest(FIRST_INDEX_NAME, songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_2;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest =  queryByIdsRequest(SECOND_INDEX_NAME, songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, song.getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));

            searchRequest = new SearchRequest(SECOND_INDEX_NAME);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
        }
    }

    @Test
    public void searchForDocumentsWithIndexPattern() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest("*".concat(INDEX_NAME_SUFFIX));

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_INDEX_NAME, FIELD_ARTIST));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest("*".concat(FIRST_INDEX_NAME));

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_2;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest =  queryByIdsRequest("*".concat(FIRST_INDEX_NAME), songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));


            songId = SECOND_INDEX_ID_SONG_3;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest =  queryByIdsRequest("*".concat(SECOND_INDEX_NAME), songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, song.getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            SearchRequest searchRequest = new SearchRequest("*".concat(FIRST_INDEX_NAME));
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));

            searchRequest = new SearchRequest("*".concat(SECOND_INDEX_NAME));
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
        }
    }

    @Test
    public void searchForDocumentsViaAlias() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));

            searchRequest = new SearchRequest(SECOND_INDEX_ALIAS);

            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_INDEX_NAME, FIELD_ARTIST));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_3;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest =  queryByIdsRequest(FIRST_INDEX_ALIAS, songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_4;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest =  queryByIdsRequest("*".concat(SECOND_INDEX_ALIAS), songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, song.getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));

            searchRequest = new SearchRequest(SECOND_INDEX_ALIAS);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
        }
    }

    @Test
    public void searchForDocumentsViaFilteredAlias() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIND_ID_OF_SONG_WITH_TITLE.apply(FIRST_INDEX_SONGS_BY_ID, TITLE_NEXT_SONG);
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS_FILTERED_BY_TWINS_ARTIST);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));

            searchRequest = new SearchRequest(FIRST_INDEX_ALIAS_FILTERED_BY_FIRST_ARTIST);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(0));
        }
    }

    @Test
    public void searchForDocumentsViaAllIndicesAlias() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_TITLE_STARS_READER)) {
            SearchRequest searchRequest = queryStringQueryRequest(ALL_INDICES_ALIAS, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_MASKED_TITLE_ARTIST_READER)) {
            String songId = FIRST_INDEX_ID_SONG_4;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest(ALL_INDICES_ALIAS, songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(song.getTitle())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, song.getLyrics()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));


            songId = SECOND_INDEX_ID_SONG_1;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest = queryByIdsRequest(ALL_INDICES_ALIAS, songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(song.getTitle())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, song.getLyrics()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_STRING_ARTIST_READER)) {
            SearchRequest searchRequest = new SearchRequest(ALL_INDICES_ALIAS);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_STRING));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));
        }
    }

    @Test
    public void scrollOverSearchResults() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(FIRST_INDEX_NAME, 2);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = searchRequestWithScroll(FIRST_INDEX_NAME, 2);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_SONGS_BY_ID.firstKey();
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = searchRequestWithScroll(FIRST_INDEX_NAME, 1);
            searchRequest.source().sort("_id", SortOrder.ASC);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            SearchRequest searchRequest = searchRequestWithScroll(FIRST_INDEX_NAME, 2);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
        }
    }

    @Test
    public void aggregateDataAndComputeAverage() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_TITLE_STARS_READER)) {
            String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), not(Double.POSITIVE_INFINITY));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(Double.POSITIVE_INFINITY));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), not(Double.POSITIVE_INFINITY));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            String aggregationName = "averageStars";
            Song song = FIRST_INDEX_SONGS_BY_ID.get(FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_TWINS));

            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(song.getStars()*1.0));
        }
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_STARS_LESS_THAN_ZERO_READER)) {
            String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(Double.POSITIVE_INFINITY));
        }
    }

    @Test
    public void getDocument() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1), DEFAULT);

            assertThat(response, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
            assertThat(response, documentContainsExactlyFieldsWithNames(FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1), DEFAULT);

            assertThat(response, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
            assertThat(response, documentContainsExactlyFieldsWithNames(FIELD_TITLE));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_4;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);
            GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, songId), DEFAULT);

            assertThat(response, containDocument(FIRST_INDEX_NAME, songId));
            assertThat(response, documentContainField(FIELD_TITLE, song.getTitle()));
            assertThat(response, documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(response, documentContainField(FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(response, documentContainField(FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_1;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);
            response = restHighLevelClient.get(new GetRequest(SECOND_INDEX_NAME, songId), DEFAULT);

            assertThat(response, containDocument(SECOND_INDEX_NAME, songId));
            assertThat(response, documentContainField(FIELD_TITLE, song.getTitle()));
            assertThat(response, documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(response, documentContainField(FIELD_ARTIST, song.getArtist()));
            assertThat(response, documentContainField(FIELD_STARS, song.getStars()));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            String songId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_TWINS);

            GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, songId), DEFAULT);

            assertThat(response, containDocument(FIRST_INDEX_NAME, songId));

            songId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_STRING);

            response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, songId), DEFAULT);

            assertThat(response, not(containDocument(FIRST_INDEX_NAME, songId)));
        }
    }

    @Test
    public void multiGetDocuments() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            MultiGetRequest request = new MultiGetRequest();
            request.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
            request.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2));

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses[0].getResponse(), allOf(
                    containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS))
            );
            assertThat(responses[1].getResponse(),  allOf(
                    containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS))
            );
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            MultiGetRequest request = new MultiGetRequest();
            request.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_3));
            request.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_4));

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses[0].getResponse(), allOf(
                    containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_3),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE))
            );
            assertThat(responses[1].getResponse(),  allOf(
                    containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_4),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE))
            );
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String firstSongId = FIRST_INDEX_ID_SONG_1;
            Song firstSong = FIRST_INDEX_SONGS_BY_ID.get(firstSongId);
            String secondSongId = SECOND_INDEX_ID_SONG_2;
            Song secondSong = SECOND_INDEX_SONGS_BY_ID.get(secondSongId);

            MultiGetRequest request = new MultiGetRequest();
            request.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, firstSongId));
            request.add(new MultiGetRequest.Item(SECOND_INDEX_NAME, secondSongId));
            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses[0].getResponse(), allOf(
                    containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1),
                    documentContainField(FIELD_TITLE, firstSong.getTitle()),
                    documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(firstSong.getLyrics())),
                    documentContainField(FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(firstSong.getArtist())),
                    documentContainField(FIELD_STARS, firstSong.getStars())
            ));
            assertThat(responses[1].getResponse(), allOf(
                    containDocument(SECOND_INDEX_NAME, secondSongId),
                    documentContainField(FIELD_TITLE, secondSong.getTitle()),
                    documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(secondSong.getLyrics())),
                    documentContainField(FIELD_ARTIST, secondSong.getArtist()),
                    documentContainField(FIELD_STARS, secondSong.getStars())
            ));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            String firstSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_NO);
            String secondSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_STRING);
            MultiGetRequest request = new MultiGetRequest();
            request.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, firstSongId));
            request.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, secondSongId));

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses[0].getResponse(), allOf(
                    not(containDocument(FIRST_INDEX_NAME, firstSongId)))
            );
            assertThat(responses[1].getResponse(), allOf(
                    not(containDocument(FIRST_INDEX_NAME, secondSongId)))
            );
        }
    }

    @Test
    public void multiSearchDocuments() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_TITLE_STARS_READER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(FIRST_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(SECOND_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();

            assertThat(responses[0].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
            assertThat(responses[1].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
        }


        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(FIRST_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(FIRST_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();

            assertThat(responses[0].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE));
            assertThat(responses[1].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_INDEX_NAME, FIELD_TITLE));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String firstSongId = FIRST_INDEX_ID_SONG_3;
            Song firstSong = FIRST_INDEX_SONGS_BY_ID.get(firstSongId);
            String secondSongId = SECOND_INDEX_ID_SONG_4;
            Song secondSong = SECOND_INDEX_SONGS_BY_ID.get(secondSongId);

            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryByIdsRequest(FIRST_INDEX_NAME, firstSongId));
            request.add(queryByIdsRequest(SECOND_INDEX_NAME, secondSongId));
            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();

            assertThat(responses[0].getResponse(), allOf(
                    searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, firstSongId),
                    searchHitContainsFieldWithValue(0, FIELD_TITLE, firstSong.getTitle()),
                    searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(firstSong.getLyrics())),
                    searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(firstSong.getArtist())),
                    searchHitContainsFieldWithValue(0, FIELD_STARS, firstSong.getStars())
            ));
            assertThat(responses[1].getResponse(), allOf(
                    searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, secondSongId),
                    searchHitContainsFieldWithValue(0, FIELD_TITLE, secondSong.getTitle()),
                    searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(secondSong.getLyrics())),
                    searchHitContainsFieldWithValue(0, FIELD_ARTIST, secondSong.getArtist()),
                    searchHitContainsFieldWithValue(0, FIELD_STARS, secondSong.getStars())
            ));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            String firstSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_TWINS);
            String secondSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(SECOND_INDEX_SONGS_BY_ID, ARTIST_FIRST);

            MultiSearchRequest request = new MultiSearchRequest();
            request.add(new SearchRequest(FIRST_INDEX_NAME));
            request.add(new SearchRequest(SECOND_INDEX_NAME));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();

            assertThat(responses[0].getResponse(), searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, firstSongId));
            assertThat(responses[0].getResponse(), searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(responses[1].getResponse(), searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, secondSongId));
            assertThat(responses[1].getResponse(), searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
        }
    }

    @Test
    public void getFieldCapabilities() throws IOException {
        //FLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(FIRST_INDEX_NAME).fields(FIELD_STARS);

            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, containsExactlyIndices(FIRST_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(0));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(FIRST_INDEX_NAME).fields(FIELD_TITLE, FIELD_ARTIST, FIELD_STARS);

            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, containsExactlyIndices(FIRST_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(1));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
        }

        //FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(FIRST_INDEX_NAME).fields(FIELD_ARTIST, FIELD_TITLE, FIELD_LYRICS);
            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, containsExactlyIndices(FIRST_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(3));
            assertThat(response, containsFieldWithNameAndType(FIELD_ARTIST, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_LYRICS, "text"));
        }

        //DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TWINS_FIRST_ARTIST_READER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(FIRST_INDEX_NAME).fields(FIELD_ARTIST, FIELD_TITLE, FIELD_LYRICS);
            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, containsExactlyIndices(FIRST_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(3));
            assertThat(response, containsFieldWithNameAndType(FIELD_ARTIST, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_LYRICS, "text"));
        }
    }

}

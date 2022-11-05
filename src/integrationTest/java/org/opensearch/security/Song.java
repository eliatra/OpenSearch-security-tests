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


import java.util.Map;
import java.util.Objects;

class Song {

	static final String FIELD_TITLE = "title";
	static final String FIELD_ARTIST = "artist";
	static final String FIELD_LYRICS = "lyrics";

	static final String FIELD_STARS = "stars";
	static final String ARTIST_FIRST = "First artist";
	static final String ARTIST_STRING = "String";
	static final String ARTIST_TWINS = "Twins";
	static final String TITLE_MAGNUM_OPUS = "Magnum Opus";
	static final String TITLE_SONG_1_PLUS_1 = "Song 1+1";
	static final String TITLE_NEXT_SONG = "Next song";
	static final String ARTIST_NO = "No!";
	static final String TITLE_POISON = "Poison";

	public static final String LYRICS_1 = "Very deep subject";
	public static final String LYRICS_2 = "Once upon a time";
	public static final String LYRICS_3 = "giant nonsense";
	public static final String LYRICS_4 = "Much too much";

	static final String QUERY_TITLE_NEXT_SONG = FIELD_TITLE + ":" + "\"" + TITLE_NEXT_SONG + "\"";
	static final String QUERY_TITLE_POISON = FIELD_TITLE + ":" + TITLE_POISON;
	static final String QUERY_TITLE_MAGNUM_OPUS = FIELD_TITLE + ":" + TITLE_MAGNUM_OPUS;

	private final String artist;
	private final String title;
	private final String lyrics;
	private final Integer stars;


	public Song(String artist, String title, String lyrics, Integer stars) {
		this.artist = Objects.requireNonNull(artist, "Artist is required");
		this.title = Objects.requireNonNull(title, "Title is required");
		this.lyrics = Objects.requireNonNull(lyrics, "Lyrics is required");
		this.stars = Objects.requireNonNull(stars, "Stars field is required");
	}

	public String getArtist() {
		return artist;
	}

	public String getTitle() {
		return title;
	}

	public String getLyrics() {
		return lyrics;
	}

	public Integer getStars() {
		return stars;
	}

	public Map<String, Object> asMap() {
		return Map.of(FIELD_ARTIST, artist,
				FIELD_TITLE, title,
				FIELD_LYRICS, lyrics,
				FIELD_STARS, stars);
	}

	static final Song[] SONGS = {
			new Song(ARTIST_FIRST, TITLE_MAGNUM_OPUS, LYRICS_1, 1),
			new Song(ARTIST_STRING, TITLE_SONG_1_PLUS_1, LYRICS_2, 2),
			new Song(ARTIST_TWINS, TITLE_NEXT_SONG, LYRICS_3, 3),
			new Song(ARTIST_NO, TITLE_POISON, LYRICS_4, 4)
	};
}

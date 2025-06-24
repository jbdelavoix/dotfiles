#!/usr/bin/env python3

import argparse
import os
import re
import subprocess

from pymediainfo import MediaInfo


def mkv_fetch_files(input_folder, output_folder, path_filter):
    mkv_files = []

    for root, _, files in os.walk(input_folder):
        for name in files:
            if not (
                name.endswith(".mkv") or name.endswith(".mp4") or name.endswith(".m2ts")
            ):
                continue

            filepath = os.path.join(root, name)

            if path_filter and path_filter.lower() not in filepath.lower():
                continue

            mkv_files.append(os.path.relpath(filepath, input_folder))

    return [
        [
            os.path.join(
                input_folder,
                partial_filepath,
            ),
            os.path.join(
                output_folder,
                partial_filepath,
            ),
        ]
        for partial_filepath in sorted(mkv_files)
    ]


def mkv_fetch_files_serie(input_folder, output_folder, path_filter):
    mkv_files = []
    max_season = 0
    max_episode = 0

    season_pattern = re.compile(
        r"[Ss](?P<seasons>[0-9-]+)[.]*[Ee](?P<episodes>[0-9-]+)(?:.*part(?P<part>[0-9]+))?"
    )

    for root, _, files in os.walk(input_folder):
        for name in files:
            if not (
                name.endswith(".mkv") or name.endswith(".mp4") or name.endswith(".m2ts")
            ):
                continue

            old_filepath = os.path.join(root, name)

            if path_filter and path_filter.lower() not in old_filepath.lower():
                continue

            match = season_pattern.search(old_filepath)
            if not match:
                continue

            data = match.groupdict()

            seasons = [int(season) for season in data["seasons"].split("-") if season]
            episodes = [
                int(episode) for episode in data["episodes"].split("-") if episode
            ]
            part = data.get("part")

            max_season = max(max_season, *seasons)
            max_episode = max(max_episode, *episodes)

            mkv_files.append([old_filepath, seasons, episodes, part])

    season_zfill = max([len(str(max_season)), 2])
    episode_zfill = max([len(str(max_episode)), 2])

    return [
        [
            old_filepath,
            os.path.join(
                output_folder,
                f"Saison {'-'.join([str(season).zfill(season_zfill) for season in seasons])}",
                f"{'-'.join([str(episode).zfill(episode_zfill) for episode in episodes])} - Episode {'-'.join([str(episode).zfill(episode_zfill) for episode in episodes])}{' (part '+part+')' if part else ''}.mkv",
            ),
        ]
        for old_filepath, seasons, episodes, part in sorted(
            mkv_files,
            key=lambda x: f"{str(x[1][0]).zfill(season_zfill)}{str(x[2][0]).zfill(episode_zfill)}{x[3]}",
        )
    ]


def mkv_file_convert(old_filepath, new_filepath, quality):
    print(f"Converting file {old_filepath}")

    escaped_old_filepath = old_filepath.replace("'", "'\\''")

    escaped_new_filepath = new_filepath.replace("'", "'\\''")

    conf = f"""
/usr/bin/ffmpeg \
-y -i '{escaped_old_filepath}' \
-map 0:v -map 0:a -map 0:s? \
-c:v copy \
-c:a ac3 -b:a 640k \
-c:s copy \
'{escaped_new_filepath}'
"""

    print(f"Execute: {conf}")
    try:
        subprocess.check_call(conf, shell=True)
    except:
        pass


def mkv_file_pass(old_filepath, new_filepath):
    print(f"Packaging file {old_filepath}")

    media_info = MediaInfo.parse(old_filepath)

    video_tracks = []
    audio_tracks = dict()
    fsst_tracks = dict()
    sst_tracks = dict()

    escaped_new_filepath = new_filepath.replace("'", "'\\''")

    conf = f""" \
mkvmerge \
--output '{escaped_new_filepath}' \
--no-track-tags \
--no-global-tags \
--no-chapters \
MKV_PROCESS_ADDITIONALS \
"""

    for track in media_info.tracks:
        if track.track_type == "Video":
            conf += f""" \
--language {track.track_id-1}:und \
--track-name {track.track_id-1}: \
--default-track {track.track_id-1}:no \
--display-dimensions {track.track_id-1}:{track.width}x{track.height} \
"""
            video_tracks += [track.track_id - 1]
        elif track.track_type == "Audio":
            language = track.other_language[-2] if track.other_language else "fra"
            language_full = (
                track.other_language[0] if track.other_language else "French"
            )
            if language not in ("eng", "fra") or language in audio_tracks:
                continue
            audio_tracks[language] = track.track_id - 1
            conf += f""" \
--language {track.track_id-1}:{language} \
--track-name {track.track_id-1}:{language_full} \
--default-track {track.track_id-1}:no \
"""
        elif track.track_type == "Text":
            language = track.other_language[-2]
            is_forced = track.forced != "No" or (
                "forced" in str(track.title or "").lower()
            )
            if language not in ("eng", "fra"):
                continue
            if is_forced:
                if language not in fsst_tracks:
                    fsst_tracks[language] = track.track_id - 1
                else:
                    continue
            else:
                if language not in sst_tracks:
                    sst_tracks[language] = track.track_id - 1
                else:
                    continue
            conf += f""" \
--language {track.track_id-1}:{track.other_language[-2]} \
--track-name '{track.track_id-1}:{track.other_language[0]}{ " (Forced)" if is_forced else ""}' \
{ "--forced-track "+str(track.track_id-1)+":yes" if is_forced else ""} \
--sub-charset {track.track_id-1}:{track.format} \
"""

    if len(video_tracks) != 1:
        raise

    escaped_old_filepath = old_filepath.replace("'", "'\\''")

    conf += f""" \
'(' '{escaped_old_filepath}' ')' \
--title "" \
"""

    audio_ids = []
    sst_ids = []
    ids = []
    ids += [f"0:{video_tracks[0]}"]

    for language in ("eng", "fra"):
        if audio_tracks.get(language):
            audio_ids += [str(audio_tracks[language])]
            ids += [f"0:{audio_tracks[language]}"]

    for language in ("eng", "fra"):
        if fsst_tracks.get(language):
            sst_ids += [str(fsst_tracks[language])]
            ids += [f"0:{fsst_tracks[language]}"]
        if sst_tracks.get(language):
            sst_ids += [str(sst_tracks[language])]
            ids += [f"0:{sst_tracks[language]}"]

    additionals = f" --audio-tracks {','.join(audio_ids)} "
    if sst_ids:
        additionals += f" --subtitle-tracks {','.join(sst_ids)}"
    additionals += " --no-attachments"

    conf = conf.replace("MKV_PROCESS_ADDITIONALS", additionals)

    conf += f"--track-order {','.join(ids)}"

    print(f"Execute: {conf}")

    try:
        subprocess.check_call(conf, shell=True)
    except:
        pass


def mkv_files_pass(input_folder, output_folder, path_filter, serie, convert, quality):
    if serie:
        filepaths = mkv_fetch_files_serie(input_folder, output_folder, path_filter)
    else:
        filepaths = mkv_fetch_files(input_folder, output_folder, path_filter)

    for old_filepath, new_filepath in filepaths:
        new_folder = os.path.dirname(new_filepath)
        if not os.path.exists(new_folder):
            os.makedirs(new_folder)
        if convert:
            filename, ext = os.path.splitext(new_filepath)
            temp_filepath = filename + ".tmp" + ext
            mkv_file_convert(old_filepath, temp_filepath, quality)
            mkv_file_pass(temp_filepath, new_filepath)
            os.remove(temp_filepath)
        else:
            mkv_file_pass(old_filepath, new_filepath)


def run():
    parser = argparse.ArgumentParser(description="Rework mkv files")
    parser.add_argument("-i", "--input", help="input folder")
    parser.add_argument("-o", "--output", help="output folder")
    parser.add_argument("-f", "--filter", help="path filter")
    parser.add_argument(
        "-s", "--serie", help="set as serie folder", action="store_true"
    )
    parser.add_argument("-c", "--convert", help="convert movies", action="store_true")
    parser.add_argument("-q", "--quality", help="convertion quality", default="24")

    args = parser.parse_args()

    mkv_files_pass(
        args.input, args.output, args.filter, args.serie, args.convert, args.quality
    )


if __name__ == "__main__":
    run()

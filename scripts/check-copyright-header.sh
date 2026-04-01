#!/usr/bin/env bash

comment_style() {
  file=$1
  ext="${file##*.}"
  case "$ext" in
      sh) echo "#"
        ;;
      go) echo "//"
        ;;
      cpp) echo "//"
        ;;
      c) echo "//"
        ;;
      java) echo "//"
        ;;
      rs) echo "//"
        ;;
      *) echo "//"
  esac
}

license() {
  year=$(date +'%Y')
  comment=$(comment_style $1)

  cat <<EOF
${comment} Copyright (c) ${year}, Circle Internet Group, Inc.
${comment} Licensed under the Apache License, Version 2.0 (the "License");
${comment} you may not use this file except in compliance with the License.
${comment} You may obtain a copy of the License at
${comment}
${comment}     http://www.apache.org/licenses/LICENSE-2.0
${comment}
${comment} Unless required by applicable law or agreed to in writing, software
${comment} distributed under the License is distributed on an "AS IS" BASIS,
${comment} WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
${comment} See the License for the specific language governing permissions and
${comment} limitations under the License.

EOF
}

files=($@)
if [ "${#files[@]}" -eq 0 ]
then
  files=($(git diff --name-only --diff-filter=AMR --cached))
fi

files_without_license=()
for file in "${files[@]}"
do
  files_without_license+=($(grep -L -E "Copyright \(c\) [0-9]{4}, Circle Internet Group, Inc\." "$file"))
done

if [ "${#files_without_license[@]}" -gt 0 ]
then
  for file in "${files_without_license[@]}"
  do
    temp=$(mktemp -p $(dirname "$file"))
    license "$file" | cat - "$file" > "$temp" && mv "$temp" "$file"
  done
  exit 1
else
  exit 0
fi

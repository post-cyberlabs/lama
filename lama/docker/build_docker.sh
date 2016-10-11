#!/bin/bash


ARGS=$(getopt -o quf: -l "quiet,update,folder:" -n "build_docker.sh" -- "$@");
#Bad arguments
if [ $? -ne 0 ];
then
  exit 1
fi
eval set -- "$ARGS";

folders=()
update=0
verbosity=""
while true; do
  case "$1" in
    -q|--quiet)
      shift;
      verbosity="-q"
      ;;
    -u|--update)
      shift;
      update=1
      ;;
    -f|--folder)
      shift;
      if [ -n "$1" ]; then
        folders+=($1)
        shift;
      fi
      ;;
    --)
      shift;
      break;
      ;;
  esac
done

# if no -f -> all folders
if [[ ${#folders[@]} = 0 ]];
then
  folders=`ls -d */ `
fi

# check if update (cf -no-cache)
if [[ $update = 1 ]];
then
  # try to update image
  update_cmd="--no-cache --pull=true"
fi


# build all Dockerfile
for dir in ${folders[@]}
do
  echo -e "\e[42mBuild $dir\e[0m"
  cmd="docker build $update_cmd $verbosity -t lama/${dir%/} $dir"
  echo -e "\e[32mBuild $cmd\e[0m"
  $cmd

done

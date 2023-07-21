#!/bin/bash
docker rm -f web_desynth_recruit
docker build --tag=web_desynth_recruit .
docker run -p 1337:1337 --rm --name=web_desynth_recruit web_desynth_recruit
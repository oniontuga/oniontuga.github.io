#!/bin/bash
docker run --rm -v /home/h3x/work/develop/h3xitsec.github.io:/srv/jekyll -p 4000:4000 -it jekyll/jekyll:latest jekyll serve
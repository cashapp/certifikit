#!/bin/sh

./build-native.sh
tar cf ./build/cft.tar build/graal/cft src/main/zsh
brew reinstall ./cft.rb

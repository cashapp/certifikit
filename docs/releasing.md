Releasing
=========

1. Update `CHANGELOG.md`.

2. Set versions:

    ```
    export RELEASE_VERSION=X.Y.Z
    export NEXT_VERSION=X.Y.Z-SNAPSHOT
    ```

3. Update the build and docs:

    ```
    sed -i "" \
      "s/version = '.*'/version = '$RELEASE_VERSION'/g" \
      build.gradle
    sed -i "" \
      "s/\"app.cash.certifikit:\([^\:]*\):[^\"]*\"/\"app.cash.certifikit:\1:$RELEASE_VERSION\"/g" \
      `find . -name "README.md"`
    sed -i "" \
      "s/\/app.cash.certifikit\/\([^\:]*\)\/[^\/]*\//\/app.cash.certifikit\/\1\/$RELEASE_VERSION\//g" \
      `find . -name "README.md"`
    ```

4. Tag the release, prepare for the next one, and push to GitHub.

    ```
    git commit -am "Prepare for release $RELEASE_VERSION."
    git tag -a certifikit-$RELEASE_VERSION -m "Version $RELEASE_VERSION"
    sed -i "" \
      "s/version = '.*'/version = '$NEXT_VERSION'/g" \
      build.gradle
    git commit -am "Prepare next development version."
    git push && git push --tags
    ```

5. Wait until the "Publish a release" action completes. If the github action fails, drop the 
   artifacts from [Sonatype Nexus] and re run the job.

6. Visit [Sonatype Nexus] to promote (close then release) the artifact. Or drop it if there is a problem!


[Sonatype Nexus]: https://oss.sonatype.org/

# Firestore rules tests

Runs `firestore.rules` against the local Firestore emulator. Nothing here touches the real project.

One-time setup (the emulator needs Java 21+; this repo's author keeps a private copy in `~/.the75-dev`):

    source ~/.the75-dev/env.sh        # puts that Java on PATH for this terminal only
    firebase setup:emulators:firestore
    (cd rules-tests && npm install)

Run:

    source ~/.the75-dev/env.sh
    RULES_MODE=new firebase emulators:exec --only firestore --project demo-the75-rules \
      "cd rules-tests && node --test --test-reporter=spec rules.test.js"

* Section A replays the write/read paths the live `index.html` uses (couple saves, signup, RSVP
  submissions, publicCouples, admin saves, settings, linen orders).
* Section B is the existing vendor-portal behaviour. A and B must pass on the old AND new rules.
* Section C (session epoch, on/off switch, pilot list) only runs with `RULES_MODE=new`.
* `RULES_FILE=path/to/other.rules` tests a different rules file (e.g. `git show main:firestore.rules`).

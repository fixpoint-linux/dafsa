-- Dhakefile.dhall — build the dafsa engine and docs site with dhake.
--
-- The dafsa engine is now Zig (zig/src; verified by zig/dafsa_diff.sh). This
-- buildfile drives the docs site (fixpointlinux.org/dafsa). The site is an Elm
-- app (src/Main.elm) rendered against the shared Fixpoint.* design package
-- (the `design` submodule) plus the mfe-framework submodule, pre-rendered by
-- scripts/ssg.mjs to static dist/.
--
-- Non-phony targets pin `hash` (expected output) and `depsHash` (expected
-- source dep) SHA-256s for verified builds — see the dhake README "Verified
-- builds". `--verify` pre-flights all pinned hashes; `--lock` writes a
-- lockfile; `--hash-uptodate` decides up-to-dateness by content, not mtime.
--
--   ./dhake/dhake.com                    # default target: dist/index.html (site)
--   ./dhake/dhake.com clean              # remove artifacts
--   ./dhake/dhake.com --verify           # CI pre-flight: check pinned hashes
--   ./dhake/dhake.com --list             # list targets
--
-- dhake itself is a git submodule (dhake/); dhake/dhake.com is the committed
-- bootstrap binary. `dhake.com` in the usage lines is `./dhake/dhake.com`.

let Action =
      < Shell : Text
      | Copy : { from : Text, to : Text }
      | Mkdir : < Plain : Text | Parents : { path : Text, parents : Bool } >
      | Rm : < Plain : Text | Recursive : { path : Text, recursive : Bool } >
      | Touch : Text
      | Move : { from : Text, to : Text }
      | Symlink : { from : Text, to : Text }
      | Chmod : { path : Text, mode : Text }
      | Echo : Text
      | Env : { key : Text, value : Text }
      | Run : { argv : List Text }
      >

let Target =
      { deps : List Text, phony : Bool, recipe : List Action
      , hash : Optional Text
      , depsHash : Optional (List { path : Text, hash : Text })
      }

in  { targets =
        [ { mapKey = "mfe-framework"
          , mapValue =
              { deps = []
              , phony = True
              , recipe = [ < Shell = "cd mfe-framework && npm ci && npm run build" > ]
              }
          }
        , { mapKey = "vendor-mfe"
          , mapValue =
              { deps = [ "mfe-framework" ]
              , phony = True
              , recipe =
                  [ < Rm = { path = "vendor/@mfe", recursive = True } >
                  , < Mkdir = { path = "vendor/@mfe/core", parents = True } >
                  , < Mkdir = { path = "vendor/@mfe/framework", parents = True } >
                  , < Shell = "cp mfe-framework/packages/core/dist/*.js vendor/@mfe/core/" >
                  , < Shell = "cp mfe-framework/packages/framework/dist/*.js vendor/@mfe/framework/" >
                  ]
              }
          }
        , { mapKey = "dist/elm.js"
          , mapValue =
              { deps = [ "src/Main.elm", "elm.json", "design/src" ]
              , phony = False
              -- expected hash of the produced dist/elm.js (verified after build).
              -- elm 0.19.2 --optimize output is byte-deterministic for identical
              -- inputs, so this pins the artifact. `design/src` is a directory
              -- and cannot be file-hashed, so it is pinned transitively via this
              -- output hash (any change to it changes the elm.js bytes).
              , hash = "sha256:8c111af3b4a7e49b4931dfee0041c96b6377eca5a5c8eb168a62c0bb571d0eff"
              , depsHash =
                  [ { path = "src/Main.elm", hash = "sha256:a8a454b680caae24b2ef78b60321132ac91125de200131bb14d14967b22bbdae" }
                  , { path = "elm.json", hash = "sha256:7a645a6d4458599521f1340b725e15795fcf43187c0c3fdff078e4bade962d5e" }
                  ]
              , recipe =
                  [ < Shell = "node_modules/elm/bin/elm make src/Main.elm --output=dist/elm.js --optimize" > ]
              }
          }
        , { mapKey = "clean"
          , mapValue =
              { deps = []
              , phony = True
              , recipe =
                  [ < Rm = { path = "libdafsa.so", recursive = False } >
                  ]
              }
          }
        , { mapKey = "dist/index.html"
          , mapValue =
              { deps =
                  [ "dist/elm.js"
                  , "vendor-mfe"
                  , "shell/index.html"
                  , "shell/shell.js"
                  , "shell/templates/dafsa.html"
                  , "scripts/ssg.mjs"
                  ]
              , phony = False
              -- expected hash of the produced dist/index.html (verified after
              -- build). The ssg output is byte-deterministic for identical
              -- inputs. `dist/elm.js` (a target) and `vendor-mfe` (phony,
              -- multi-file) are verified transitively via this output hash.
              , hash = "sha256:f7c4180bfd20218a42ca8b35ef814b19022db94a703e530c4620e587780268f4"
              , depsHash =
                  [ { path = "shell/index.html", hash = "sha256:4b86056e243b1bba7af0ebc0287db712cb2f8588717a055e9ba4513529bdddcc" }
                  , { path = "shell/shell.js", hash = "sha256:71360de5795fa9a9e7d3d5549e18625415a2bed5c5eb34c6f61a6b6ed59f8463" }
                  , { path = "shell/templates/dafsa.html", hash = "sha256:06d0b13a0ecf6c43e4a2e04ce6a711fdf7fac446c360a4d7f7efaea60a694ec4" }
                  , { path = "scripts/ssg.mjs", hash = "sha256:97a3e03492ae475fb50f13a7841f62ec47a1c724d57b8605e88e4cb07d10c6e5" }
                  ]
              , recipe = [ < Shell = "node scripts/ssg.mjs" > ]
              }
          }
        ]
      , default = "dist/index.html"
      }

-- Dhakefile.dhall — build the dafsa engine and docs site with dhake.
--
-- Both the C engine (`libdafsa.so`, formerly the Makefile) and the docs site
-- (fixpointlinux.org/dafsa) are driven by this single buildfile. The site is
-- an Elm app (src/Main.elm) rendered against the shared Fixpoint.* design
-- package (the `design` submodule) plus the mfe-framework submodule,
-- pre-rendered by scripts/ssg.mjs to static dist/.
--
--   ./dhake/dhake.com                    # default target: dist/index.html (site)
--   ./dhake/dhake.com libdafsa.so        # build the C engine (shared lib)
--   ./dhake/dhake.com clean              # remove objects + lib
--   ./dhake/dhake.com --list             # list targets
--
-- dhake.com is the vendored bootstrap binary (committed); the build driver.

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
              , recipe =
                  [ < Shell = "node_modules/elm/bin/elm make src/Main.elm --output=dist/elm.js --optimize" > ]
              }
          }
        , { mapKey = "libdafsa.so"
          , mapValue =
              { deps =
                  [ "dafsa.c"
                  , "dafsa_state.c"
                  , "dafsa_core.c"
                  , "dafsa_persist.c"
                  , "dafsa_view.c"
                  , "dafsa_crc32.c"
                  , "dafsa_wal.c"
                  , "dafsa_build.c"
                  , "dafsa_rank.c"
                  , "dafsa_view_rank.c"
                  ]
              , phony = False
              , recipe =
                  [ < Shell = "gcc -O2 -Wall -Wextra -Werror -std=c11 -fPIC -D_POSIX_C_SOURCE=200809L -I. -c dafsa.c dafsa_state.c dafsa_core.c dafsa_persist.c dafsa_view.c dafsa_crc32.c dafsa_wal.c dafsa_build.c dafsa_rank.c dafsa_view_rank.c" >
                  , < Shell = "gcc -shared -fPIC -O2 -Wall -Wextra -Werror -std=c11 -fPIC -D_POSIX_C_SOURCE=200809L -I. -o libdafsa.so dafsa.o dafsa_state.o dafsa_core.o dafsa_persist.o dafsa_view.o dafsa_crc32.o dafsa_wal.o dafsa_build.o dafsa_rank.o dafsa_view_rank.o" >
                  ]
              }
          }
        , { mapKey = "clean"
          , mapValue =
              { deps = []
              , phony = True
              , recipe =
                  [ < Rm = { path = "libdafsa.so", recursive = False } >
                  , < Shell = "rm -f dafsa.o dafsa_state.o dafsa_core.o dafsa_persist.o dafsa_view.o dafsa_crc32.o dafsa_wal.o dafsa_build.o dafsa_rank.o dafsa_view_rank.o" >
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
              , recipe = [ < Shell = "node scripts/ssg.mjs" > ]
              }
          }
        ]
      , default = "dist/index.html"
      }

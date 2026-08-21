-- Dhakefile.dhall — build the dafsa docs site with dhake.
--
-- The engine itself is built by the Makefile (`make` -> libdafsa.so). This
-- Dhakefile only drives the docs site (fixpointlinux.org/dafsa), an Elm app
-- (src/Main.elm) rendered against the shared Fixpoint.* design package (the
-- `design` submodule) plus the mfe-framework submodule, pre-rendered by
-- scripts/ssg.mjs to static dist/.
--
--   ./dhake/dhake.com                    # default target: dist/index.html
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

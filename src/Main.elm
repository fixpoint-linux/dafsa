module Main exposing (main)

{-| The dafsa documentation page as a plain `Browser.element` app.

This module renders the entire dafsa docs page — top nav, hero, and the
`#about` / `#engine` / `#api` / `#persistence` / `#consumers` / `#build`
sections plus footer — using the shared `Fixpoint.*` design package
(`design/src` is a source-directory in this application's `elm.json`).

The first child of the view is `Fixpoint.Style.stylesheet`, which emits the full
brand stylesheet as a single `<style>` node. Because the page is pre-rendered
under happy-dom by `scripts/ssg.mjs`, that `<style>` node is carried into the
static HTML — the styling ships with the page instead of living in a committed
stylesheet.

It is rendered at build time only: `scripts/ssg.mjs` loads the compiled bundle
under happy-dom and calls `Elm.Main.init({ node })` to pre-render the page to
static `dist/index.html`. There is no client-side interactivity (the model is
unit, the only message is `NoOp`).

Content is faithful to the canonical DAFSA engine in this repo: the
Carrasco–Forcada incremental minimal-acyclic DFA in C11, split across a
multi-file engine with a write-ahead log and an mmap zero-copy layered view,
consumed as a git submodule by datalog-dafsa and jing-meta.

-}

import Browser
import Fixpoint.Card
import Fixpoint.Checks
import Fixpoint.Code
import Fixpoint.Footer
import Fixpoint.Grid
import Fixpoint.Hero
import Fixpoint.Nav
import Fixpoint.Section
import Fixpoint.Style
import Html exposing (Html, a, b, div, em, li, p, span, text)
import Html.Attributes exposing (attribute, class, href)


main : Program () Model Msg
main =
    Browser.element
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        }



-- MODEL


type alias Model =
    ()


type Msg
    = NoOp


init : () -> ( Model, Cmd Msg )
init _ =
    ( (), Cmd.none )


update : Msg -> Model -> ( Model, Cmd Msg )
update _ model =
    ( model, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none



-- VIEW


view : Model -> Html Msg
view _ =
    div []
        [ Fixpoint.Style.stylesheet
        , navView
        , headerView
        , aboutSection
        , engineSection
        , apiSection
        , persistenceSection
        , consumersSection
        , buildSection
        , footerView
        ]



-- Top nav (brand + anchor links)


navView : Html Msg
navView =
    Fixpoint.Nav.view
        { brand =
            span []
                [ span [ class "fx" ] [ text "fx" ]
                , text "://dafsa"
                ]
        , links =
            [ a [ class "home", href "https://fixpointlinux.org/", attribute "data-mfe-route" "/" ]
                [ text "fixpoint-linux" ]
            , Fixpoint.Nav.link "#about" "about"
            , Fixpoint.Nav.link "#engine" "engine"
            , Fixpoint.Nav.link "#api" "api"
            , Fixpoint.Nav.link "#persistence" "persistence"
            , Fixpoint.Nav.link "#consumers" "consumers"
            , Fixpoint.Nav.link "#build" "build"
            ]
        , extra = []
        }



-- Hero


headerView : Html Msg
headerView =
    Fixpoint.Hero.view
        { prompt =
            [ Fixpoint.Hero.hash
            , text " dafsa "
            , Fixpoint.Hero.dollar
            , text " make"
            , Fixpoint.Hero.blink
            ]
        , title =
            [ text "A minimal automaton you can "
            , Fixpoint.Hero.fx [ text "build incrementally" ]
            , text "."
            ]
        , tagline =
            [ b [] [ text "Carrasco–Forcada" ]
            , text " clone-on-write + register + confluence — add and delete keys while keeping the machine minimal. A split "
            , b [] [ text "C11" ]
            , text " engine: length-delimited keys, an mmap zero-copy "
            , b [] [ text "layered view"
            ]
            , text ", and a "
            , b [] [ text "write-ahead log"
            ]
            , text "."
            ]
        }



-- Section: #about


aboutSection : Html Msg
aboutSection =
    Fixpoint.Section.view
        { id = "about"
        , title = "What it is"
        , hint = "// incremental construction & maintenance of a minimal acyclic DFA"
        , children =
            [ p []
                [ text "A DAFSA (also called a DAWG — directed acyclic word graph) is a minimized, deterministic, acyclic finite-state automaton that represents a set of strings/keys. Unlike a trie, shared suffixes are merged, so common prefixes "
                , em [] [ text "and"
                ]
                , text " suffixes collapse into shared states, yielding a compact representation."
                ]
            , p []
                [ text "Unlike a batch-built automaton, this implementation supports "
                , Fixpoint.Code.inline "add"
                , text " and "
                , Fixpoint.Code.inline "delete"
                , text " of individual keys while keeping the automaton minimal after every operation, following Carrasco & Forcada (2002):"
                ]
            , Fixpoint.Checks.view
                [ li [] [ text "Clone-on-write — split a shared state before diverging from it." ]
                , li [] [ text "A register (open-addressing hash table) keyed by state signature to detect isomorphic states and merge them." ]
                , li [] [ text "Confluence — rerouting incoming transitions so the machine stays minimal." ]
                ]
            , p []
                [ text "Keys are "
                , Fixpoint.Code.inline "_n"
                , text " length-delimited, so they may contain embedded "
                , Fixpoint.Code.inline "NUL"
                , text " bytes."
                ]
            ]
        }



-- Section: #engine


engineSection : Html Msg
engineSection =
    Fixpoint.Section.view
        { id = "engine"
        , title = "Split engine layout"
        , hint = "// multi-file C, built to libdafsa.so"
        , children =
            [ p []
                [ text "This is the canonical DAFSA engine for the fixpoint-linux stack — a split multi-file implementation (not a single monolithic "
                , Fixpoint.Code.inline ".c"
                , text "), consumed as a git submodule by downstream projects."
                ]
            , Fixpoint.Code.block
                [ text "dafsa.h            "
                , Fixpoint.Code.c "# public opaque API"
                , text "\n"
                , text "dafsa_internal.h    "
                , Fixpoint.Code.c "# shared internal decls"
                , text "\n"
                , text "dafsa.c             "
                , Fixpoint.Code.c "# public entry, driver"
                , text "\n"
                , text "dafsa_state.c       "
                , Fixpoint.Code.c "# state + register"
                , text "\n"
                , text "dafsa_core.c        "
                , Fixpoint.Code.c "# add/delete/lookup core"
                , text "\n"
                , text "dafsa_persist.c     "
                , Fixpoint.Code.c "# save/load (PDWG v4)"
                , text "\n"
                , text "dafsa_view.c        "
                , Fixpoint.Code.c "# mmap read-only view"
                , text "\n"
                , text "dafsa_wal.c         "
                , Fixpoint.Code.c "# write-ahead log"
                , text "\n"
                , text "dafsa_crc32.c       "
                , Fixpoint.Code.c "# sidecar checksum"
                , text "\n"
                , text "dafsa_build.c       "
                , Fixpoint.Code.c "# bulk minimal build"
                , text "\n"
                , text "dafsa_rank.c        "
                , Fixpoint.Code.c "# rank/serialization"
                , text "\n"
                , text "dafsa_view_rank.c   "
                , Fixpoint.Code.c "# ranked view helpers"
                ]
            ]
        }



-- Section: #api


apiSection : Html Msg
apiSection =
    Fixpoint.Section.view
        { id = "api"
        , title = "C API"
        , hint = "// opaque dafsa handle · length-delimited keys"
        , children =
            [ Fixpoint.Grid.grid
                [ Fixpoint.Card.view
                    { n = "01"
                    , title = "Lifecycle"
                    , body =
                        [ Fixpoint.Code.inline "dafsa_create"
                        , text " / "
                        , Fixpoint.Code.inline "dafsa_free"
                        , text " manage an opaque heap handle with growable state — no fixed static arrays, no per-edge malloc/free."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "02"
                    , title = "Mutate & query"
                    , body =
                        [ Fixpoint.Code.inline "dafsa_add_n"
                        , text " / "
                        , Fixpoint.Code.inline "dafsa_lookup_n"
                        , text " / "
                        , Fixpoint.Code.inline "dafsa_delete_n"
                        , text " (plus NUL-terminated "
                        , Fixpoint.Code.inline "add"
                        , text " / "
                        , Fixpoint.Code.inline "lookup"
                        , text " / "
                        , Fixpoint.Code.inline "delete"
                        , text " wrappers) work on length-delimited keys."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "03"
                    , title = "Bulk build"
                    , body =
                        [ Fixpoint.Code.inline "dafsa_build_sorted"
                        , text " constructs a minimal automaton from a sorted, deduplicated key list (Daciuk et al.), the fast path for large initial corpora."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "04"
                    , title = "Enumerate & inspect"
                    , body =
                        [ Fixpoint.Code.inline "dafsa_prefix_enum"
                        , text " enumerates hits under a prefix; "
                        , Fixpoint.Code.inline "dafsa_stats"
                        , text " reports state/transition counts; "
                        , Fixpoint.Code.inline "dafsa_dot"
                        , text " exports a Graphviz description; "
                        , Fixpoint.Code.inline "dafsa_abi_version"
                        , text " reports the ABI."
                        ]
                    }
                ]
            , p []
                [ text "Portably "
                , Fixpoint.Code.inline "C11"
                , text " — builds with a system "
                , Fixpoint.Code.inline "cc"
                , text " (see the Makefile) into a shared "
                , Fixpoint.Code.inline "libdafsa.so"
                , text "."
                ]
            ]
        }



-- Section: #persistence


persistenceSection : Html Msg
persistenceSection =
    Fixpoint.Section.view
        { id = "persistence"
        , title = "Persistence & write-ahead log"
        , hint = "// PDWG v4 · WAL append/replay · mmap layered view"
        , children =
            [ p []
                [ Fixpoint.Code.inline "dafsa_save"
                , text " / "
                , Fixpoint.Code.inline "dafsa_load"
                , text " persist the automaton to the compact "
                , Fixpoint.Code.inline "PDWG v4"
                , text " on-disk format. "
                , Fixpoint.Code.inline "dafsa_load_readonly"
                , text " mmaps the file for a read-only, zero-copy fast path — search-only, skipping the inode/register rebuild."
                ]
            , p []
                [ text "A "
                , Fixpoint.Code.inline "write-ahead log"
                , text " ("
                , Fixpoint.Code.inline "dafsa_wal_*"
                , text ") records "
                , Fixpoint.Code.inline "append_add"
                , text " / "
                , Fixpoint.Code.inline "append_del"
                , text " operations for crash-consistent, replayable updates: "
                , Fixpoint.Code.inline "dafsa_wal_replay"
                , text " applies them back into the automaton. "
                , Fixpoint.Code.inline "dafsa_view_open_layered"
                , text " layers a mmap'd base index with the WAL for a fast read path over recent writes."
                ]
            , Fixpoint.Code.block
                [ Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "dafsa_view_open"
                , text "(fst_path)            "
                , Fixpoint.Code.c "# mmap, search-only, zero-copy"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "dafsa_view_open_layered"
                , text "(fst_path, wal_path) "
                , Fixpoint.Code.c "# base index + WAL overlay"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "dafsa_load"
                , text "(path)                 "
                , Fixpoint.Code.c "# read-write, rebuilds inode/register"
                ]
            ]
        }



-- Section: #consumers


consumersSection : Html Msg
consumersSection =
    Fixpoint.Section.view
        { id = "consumers"
        , title = "Consumers"
        , hint = "// consumed as a git submodule"
        , children =
            [ Fixpoint.Grid.grid
                [ Fixpoint.Card.view
                    { n = "01"
                    , title = "datalog-dafsa"
                    , body =
                        [ text "A DAFSA-backed Datalog engine in C. Uses this engine at "
                        , Fixpoint.Code.inline "vendor/dafsa"
                        , text " for bulk minimal build + rank + view."
                        ]
                    }
                , Fixpoint.Card.view
                    { n = "02"
                    , title = "jing-meta"
                    , body =
                        [ text "A full-text indexer. Uses this engine at "
                        , Fixpoint.Code.inline "indexer/dafsa/vendor/dafsa"
                        , text " and keeps its own "
                        , Fixpoint.Code.inline "dafsa_build.c"
                        , text " "
                        , Fixpoint.Code.inline "build_main"
                        , text " locally."
                        ]
                    }
                ]
            ]
        }



-- Section: #build


buildSection : Html Msg
buildSection =
    Fixpoint.Section.view
        { id = "build"
        , title = "Build"
        , hint = "// make → libdafsa.so · dhake → docs site"
        , children =
            [ p []
                [ text "The engine is built with "
                , Fixpoint.Code.inline "make"
                , text " into a shared "
                , Fixpoint.Code.inline "libdafsa.so"
                , text ". The docs site is built with "
                , a [ href "https://github.com/fixpoint-linux/dhake" ] [ text "dhake"
                ]
                , text " (an Elm app rendered against the Fixpoint design package)."
                ]
            , Fixpoint.Code.block
                [ Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "make"
                , text "                  "
                , Fixpoint.Code.c "# build libdafsa.so"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "make"
                , text " clean            "
                , Fixpoint.Code.c "# remove objects + lib"
                , text "\n"
                , Fixpoint.Code.k "$"
                , text " "
                , Fixpoint.Code.g "./dhake/dhake.com"
                , text "          "
                , Fixpoint.Code.c "# build dist/index.html (docs site)"
                ]
            ]
        }



-- Footer


footerView : Html Msg
footerView =
    Fixpoint.Footer.view
        [ a [ href "https://github.com/fixpoint-linux/dafsa" ]
            [ text "github.com/fixpoint-linux/dafsa" ]
        , Fixpoint.Footer.sep
        , text "part of "
        , a [ href "https://fixpointlinux.org" ] [ text "fixpoint-linux" ]
        ]

(ns com-backblaze-secure.credentials
  "Resolves per-bucket B2 credentials via env → 1password → keychain, in
  that order — the same shape and precedence as this workspace's
  `manifest/repos.edn` `:b2 :credentials` (see root `scripts/b2-creds.cljs`),
  generalized from a single hardcoded bucket to any number of named buckets
  declared in `config/*.edn`. No new secret-storage scheme is invented.

  Never logs, prints, or returns the resolved secret itself — the only
  values this ns produces are {:key-id :app-key} maps meant to be passed
  straight into a single `b2` subprocess call's environment
  (com-backblaze-secure.b2-cli) and then dropped."
  (:require [clojure.string :as str]))

(def child-process (js/require "node:child_process"))

;; `op read` in particular hangs indefinitely rather than failing fast when
;; the 1Password CLI session has expired and it falls back to an
;; interactive re-auth prompt that a non-TTY child process can never answer
;; (confirmed empirically — without this timeout, a single stale `op`
;; session hangs the whole stdio server on the very first tool call). Every
;; credential-resolution subprocess gets a short, fixed timeout: these calls
;; must always be near-instant, so a wait this long only ever means "this
;; source is unavailable, fall through to the next one."
(def resolve-timeout-ms 5000)

(defn- sh [cmd args]
  (try
    ;; `execFileSync`'s default `stdio` INHERITS the child's stderr straight
    ;; through to this process's own stderr (Node's own documented, widely
    ;; footgun-prone default) — confirmed empirically: `security
    ;; find-generic-password -g` prints the resolved secret in cleartext on
    ;; its own stderr as part of a human-readable attribute dump, and
    ;; without this explicit `:stdio` override that plaintext secret would
    ;; leak straight onto this server's stderr (logs, terminal, whatever is
    ;; watching the process) on every single keychain resolution. Explicit
    ;; `["ignore" "pipe" "pipe"]` captures stdout/stderr into the buffers we
    ;; actually read below instead of ever writing them anywhere else.
    {:exit 0 :out (.toString (.execFileSync child-process cmd (clj->js args)
                                            #js {:encoding "utf8" :timeout resolve-timeout-ms
                                                 :stdio (clj->js ["ignore" "pipe" "pipe"])}))}
    (catch :default e
      {:exit 1 :out "" :err (.-message e)})))

(defn- from-env [env-name]
  (when env-name
    (let [v (aget js/process.env env-name)]
      (when (and v (not= v "")) v))))

(defn- from-1password [ref]
  (when ref
    (let [{:keys [exit out]} (sh "op" ["read" ref])]
      (when (zero? exit) (str/trim out)))))

(defn- from-keychain-combined
  "Single-item macOS Keychain layout: `security add-generic-password -s
  <service> -a <key-id> -w <app-key>` — account = key-id, password =
  app-key. Mirrors scripts/b2-creds.cljs's :combined keychain mode."
  [service field]
  (case field
    :app-key (let [{:keys [exit out]} (sh "security" ["find-generic-password" "-s" service "-w"])]
               (when (zero? exit) (str/trim out)))
    :key-id  (let [{:keys [exit out]} (sh "security" ["find-generic-password" "-s" service "-g"])]
               (when (zero? exit)
                 (some-> (re-find #"\"acct\"<blob>=\"([^\"]*)\"" out) second)))
    nil))

(defn- resolve-field
  [cred field]
  (some (fn [src]
          (case src
            :env       (from-env (get-in cred [:env field]))
            :1password (from-1password (get-in cred [:1password field]))
            :keychain  (let [svc (get-in cred [:keychain :service])]
                         (when svc (from-keychain-combined svc field)))
            nil))
        (or (:order cred) [:env :1password :keychain])))

(defn resolve-credentials
  "`cred` is one bucket's `:credentials` map from config/*.edn: {:order
  [...] :env {:key-id \"ENV_NAME\" :app-key \"ENV_NAME\"} :1password {:key-id
  \"op://...\" :app-key \"op://...\"} :keychain {:service \"b2:<name>\"}}.
  Returns {:key-id :app-key}. Throws (never returns partial/placeholder
  secret material) if either field cannot be resolved from any configured
  source."
  [cred]
  (let [key-id  (resolve-field cred :key-id)
        app-key (resolve-field cred :app-key)]
    (when-not key-id
      (throw (js/Error. "could not resolve :key-id (checked env/1password/keychain)")))
    (when-not app-key
      (throw (js/Error. "could not resolve :app-key (checked env/1password/keychain)")))
    {:key-id key-id :app-key app-key}))

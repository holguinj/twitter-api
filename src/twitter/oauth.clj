(ns twitter.oauth
  (:use
   [clojure.test])
  (:require
   [http.async.client.request :as req]
   [http.async.client :refer [create-client]]
   [twitter.callbacks :refer [callbacks-sync-single-default]]
   [twitter.request :refer [execute-request-callbacks]]
   [clojure.data.codec.base64 :as b64]
   [oauth.client :as oa]
   [oauth.signature :as oas]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

 (defrecord OauthCredentials
    [consumer
     #^String access-token
     #^String access-token-secret])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn sign-query
  "takes oauth credentials and returns a map of the signing parameters"
  [#^OauthCredentials oauth-creds verb uri & {:keys [query]}]

  (if oauth-creds
    (into (sorted-map)
          (merge {:realm "Twitter API"}
                 (oa/credentials (:consumer oauth-creds)
                                 (:access-token oauth-creds)
                                 (:access-token-secret oauth-creds)
                                 verb
                                 uri
                                 query)))))
  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn oauth-header-string 
  "creates the string for the oauth header's 'Authorization' value, url encoding each value"
  [signing-map & {:keys [url-encode?] :or {url-encode? true}}]
  (println "Signing map:" signing-map)

  (if-let [app-only-token (:bearer signing-map)]
    (str "Bearer " app-only-token)
    (let [val-transform (if url-encode? oas/url-encode identity)
          s (reduce (fn [s [k v]] (format "%s%s=\"%s\"," s (name k) (val-transform (str v))))
                    "OAuth "
                    signing-map)]
      (.substring s 0 (dec (count s))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn make-oauth-creds
  "creates an oauth object out of supplied params"
  [app-key app-secret user-token user-token-secret]

  (let [consumer (oa/make-consumer app-key
                                   app-secret
                                   "https://twitter.com/oauth/request_token"
                                   "https://twitter.com/oauth/access_token"
                                   "https://twitter.com/oauth/authorize"
                                   :hmac-sha1)]
        
    (OauthCredentials. consumer user-token user-token-secret)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn encode-app-only-key
  [consumer-key consumer-secret]
  ;; TODO: RFC 1738-encode keys for no reason
  (let [concat-keys (str consumer-key ":" consumer-secret)]
    (-> (.getBytes concat-keys)
      b64/encode
      (String. "UTF-8"))
;    (String. (b64/encode (.getBytes concat-keys)) "UTF-8")
    ))

(defn prepare-post
  [url headers body]
  (req/prepare-request :post, url,
                       :headers headers
                       :body body))

(defn request-app-only-token
  [consumer-key consumer-secret]
  (let [req (prepare-post "https://api.twitter.com/oauth2/token"
                          {"Authorization" (str "Basic "
                                                (encode-app-only-key consumer-key consumer-secret))
                           "Content-Type" "application/x-www-form-urlencoded;charset=UTF-8"}
                          "grant_type=client_credentials")
        client (create-client :follow-redirects false :request-timeout -1)
        {:keys [status body]} (execute-request-callbacks client req (callbacks-sync-single-default))]
    (if (= (:code status) 200)
      {:bearer (:access_token body)}
      (throw (Exception. "Failed to retrieve application-only token")))))

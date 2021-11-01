# Python standard libraries
import json
import os

from flask.templating import render_template

from dotenv import load_dotenv

load_dotenv()

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Third-party libraries
from flask import Flask, redirect, request, url_for, session
from oauthlib.oauth2 import WebApplicationClient
import requests


# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)


client = WebApplicationClient(GOOGLE_CLIENT_ID)


@app.route("/")
def index():
    access_token = session.get("access_token")
    if access_token:
        return render_template(
            "index.html",
            access_token=access_token,
            username=session.get("username"),
            picture=session.get("picture"),
            email=session.get("email"),
        )

    return render_template("login.html")


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@app.route("/login", methods=["POST"])
def login():
    nonce = request.form.get("nonce")
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
        nonce=nonce,
    )

    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    session["access_token"] = token_response.json().get("id_token")

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        session["email"] = userinfo_response.json()["email"]
        session["picture"] = userinfo_response.json()["picture"]
        session["username"] = userinfo_response.json()["given_name"]

        return redirect(url_for("index"))
    else:
        return "User email not available or not verified by Google.", 400


@app.route("/logout")
def logout():
    session["access_token"] = None
    session["email"] = None
    session["picture"] = None
    session["username"] = None

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(ssl_context="adhoc")

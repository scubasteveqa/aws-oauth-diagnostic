import base64
import json

import boto3
from posit import connect
from shiny import reactive, render
from shiny.express import input, session, ui


STS_REGION = "us-east-1"


ui.page_opts(title="AWS OAuth Diagnostic", fillable=False)


@reactive.calc
def session_token():
    return session.http_conn.headers.get("Posit-Connect-User-Session-Token")


@reactive.calc
def connect_client():
    return connect.Client()


@reactive.calc
def current_content():
    return connect_client().content.get()


@reactive.calc
def associations():
    try:
        return list(current_content().oauth.associations.find())
    except Exception as e:
        return e


def _decode_aws_creds(creds: dict):
    """Decode the AWS template's get_credentials() response.

    For the AWS template, vivid-api returns:
      {
        "access_token": <base64(json({accessKeyId, secretAccessKey, sessionToken, expiration}))>,
        "issued_token_type": "urn:ietf:params:aws:token-type:credentials",
        "token_type": "bearer"
      }
    Returns (decoded_dict, error_str). On success, error_str is None.
    """
    encoded = creds.get("access_token")
    if not encoded:
        return None, "creds.access_token is empty/missing"
    try:
        raw_bytes = base64.b64decode(encoded)
    except Exception as e:
        return None, f"base64 decode failed: {type(e).__name__}: {e}"
    try:
        text = raw_bytes.decode("utf-8")
    except Exception as e:
        return None, f"utf-8 decode failed: {type(e).__name__}: {e} (first 60 bytes: {raw_bytes[:60]!r})"
    try:
        decoded = json.loads(text)
    except Exception as e:
        return None, f"JSON parse failed: {type(e).__name__}: {e} (decoded text first 200 chars: {text[:200]!r})"
    return decoded, None


with ui.card():
    ui.card_header("Status")

    @render.ui
    def status_display():
        token = session_token()
        items = [ui.tags.li(f"Session token present: {bool(token)}")]
        if token:
            items.append(ui.tags.li(f"Token prefix: {token[:20]}..."))
        try:
            c = current_content()
            items.append(ui.tags.li(f"Content GUID: {c.get('guid')}"))
            items.append(ui.tags.li(f"Content title: {c.get('title')}"))
        except Exception as e:
            items.append(ui.tags.li(f"Content lookup error: {type(e).__name__}: {e}"))
        items.append(ui.tags.li(f"STS region: {STS_REGION}"))
        return ui.tags.ul(*items)


with ui.card():
    ui.card_header("Associated integrations on this content")

    @render.ui
    def integrations_display():
        assocs = associations()
        if isinstance(assocs, Exception):
            return ui.div(
                ui.tags.strong(f"Error ({type(assocs).__name__})"),
                ui.tags.pre(str(assocs)),
                class_="alert alert-danger",
            )
        if not assocs:
            return ui.div(
                "No integrations associated with this content.",
                class_="alert alert-warning",
            )
        rows = []
        for a in assocs:
            guid = a.get("oauth_integration_guid")
            name = a.get("oauth_integration_name")
            type_ = a.get("oauth_integration_type")
            rows.append(ui.tags.li(f"{name} — type={type_} — guid={guid}"))
        return ui.tags.ul(*rows)


with ui.card():
    ui.card_header("Step 1: Exchange session token for AWS credentials")
    ui.markdown(
        "Calls `connect.Client().oauth.get_credentials(token)` to retrieve AWS "
        "temporary credentials from Posit Connect. Connect Cloud performs the IDP "
        "OAuth flow and the AWS STS `AssumeRoleWithWebIdentity` exchange internally; "
        "the response's `access_token` is base64-encoded JSON containing the AWS "
        "`accessKeyId`, `secretAccessKey`, `sessionToken`, and `expiration`."
    )
    ui.input_action_button("get_creds", "Get credentials", class_="btn-primary")

    @render.ui
    def creds_result():
        if input.get_creds() == 0:
            return ui.div("Not yet called.", class_="text-muted")
        token = session_token()
        if not token:
            return ui.div("No session token available.", class_="alert alert-warning")
        try:
            creds = connect_client().oauth.get_credentials(token)
        except Exception as e:
            return ui.div(
                ui.tags.strong(f"ERROR ({type(e).__name__})"),
                ui.tags.pre(str(e)),
                class_="alert alert-danger",
            )

        raw_access_token = creds.get("access_token", "")
        decoded, err = _decode_aws_creds(creds)
        if err:
            return ui.div(
                ui.tags.strong("PARTIAL — credentials fetched but decoding failed"),
                ui.tags.pre(f"keys: {list(creds.keys())}"),
                ui.tags.pre(f"access_token (first 60 chars): {str(raw_access_token)[:60]!r}"),
                ui.tags.pre(f"access_token length: {len(str(raw_access_token))}"),
                ui.tags.pre(f"decode error: {err}"),
                class_="alert alert-warning",
            )
        return ui.div(
            ui.tags.strong("SUCCESS"),
            ui.tags.pre(f"keys: {list(creds.keys())}"),
            ui.tags.pre(f"decoded keys: {list(decoded.keys())}"),
            ui.tags.pre(f"accessKeyId (first 12 chars): {str(decoded.get('accessKeyId'))[:12]}..."),
            ui.tags.pre(f"expiration: {decoded.get('expiration')}"),
            class_="alert alert-success",
        )


with ui.card():
    ui.card_header("Step 2: Verify AWS auth with STS GetCallerIdentity")
    ui.markdown(
        "Uses the AWS credentials from Step 1 to call **`sts.get_caller_identity()`**. "
        "This call requires zero IAM permissions — every principal can call it on "
        "themselves — so it's the cleanest way to prove federation worked. The response "
        "echoes back the assumed-role ARN, the AWS account ID, and the unique session ID."
    )
    ui.input_action_button("verify_auth", "Call GetCallerIdentity", class_="btn-primary")

    @render.ui
    def verify_result():
        if input.verify_auth() == 0:
            return ui.div("Not yet called.", class_="text-muted")
        token = session_token()
        if not token:
            return ui.div("No session token available.", class_="alert alert-warning")
        try:
            creds = connect_client().oauth.get_credentials(token)
        except Exception as e:
            return ui.div(
                ui.tags.strong(f"Credential exchange failed ({type(e).__name__})"),
                ui.tags.pre(str(e)),
                class_="alert alert-danger",
            )
        decoded, err = _decode_aws_creds(creds)
        if err:
            return ui.div(
                ui.tags.strong("ERROR — couldn't decode credentials response"),
                ui.tags.pre(f"keys: {list(creds.keys())}"),
                ui.tags.pre(f"decode error: {err}"),
                class_="alert alert-danger",
            )
        access_key = decoded.get("accessKeyId")
        secret_key = decoded.get("secretAccessKey")
        session_tok = decoded.get("sessionToken")
        if not (access_key and secret_key and session_tok):
            return ui.div(
                ui.tags.strong("ERROR"),
                ui.tags.pre("Decoded credentials missing one of: accessKeyId, secretAccessKey, sessionToken"),
                ui.tags.pre(f"decoded keys: {list(decoded.keys())}"),
                class_="alert alert-danger",
            )
        try:
            sts = boto3.client(
                "sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_tok,
                region_name=STS_REGION,
            )
            identity = sts.get_caller_identity()
            return ui.div(
                ui.tags.strong("SUCCESS — AWS accepted the federated credentials"),
                ui.tags.pre(f"Account: {identity.get('Account')}"),
                ui.tags.pre(f"ARN: {identity.get('Arn')}"),
                ui.tags.pre(f"UserId: {identity.get('UserId')}"),
                class_="alert alert-success",
            )
        except Exception as e:
            return ui.div(
                ui.tags.strong(f"AWS STS call failed ({type(e).__name__})"),
                ui.tags.pre(str(e)),
                class_="alert alert-danger",
            )

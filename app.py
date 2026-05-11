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


def _extract_aws_creds(creds: dict):
    """Pull AWS credentials out of the get_credentials() response.

    Posit Connect may return them in snake_case (access_key_id) or PascalCase
    (AccessKeyId) depending on SDK version, so try both.
    """
    access_key = creds.get("access_key_id") or creds.get("AccessKeyId")
    secret_key = creds.get("secret_access_key") or creds.get("SecretAccessKey")
    session_tok = creds.get("session_token") or creds.get("SessionToken")
    expiration = creds.get("expiration") or creds.get("Expiration")
    return access_key, secret_key, session_tok, expiration


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
        "what comes back are short-lived AWS credentials (access key, secret key, "
        "session token) scoped to the role configured on the integration."
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
        access_key, _, _, expiration = _extract_aws_creds(creds)
        return ui.div(
            ui.tags.strong("SUCCESS"),
            ui.tags.pre(f"keys: {list(creds.keys())}"),
            ui.tags.pre(f"access_key_id (first 12 chars): {str(access_key)[:12]}..."),
            ui.tags.pre(f"expiration: {expiration}"),
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
        access_key, secret_key, session_tok, _ = _extract_aws_creds(creds)
        if not (access_key and secret_key and session_tok):
            return ui.div(
                ui.tags.strong("ERROR"),
                ui.tags.pre("Credentials response missing one of: access_key_id, secret_access_key, session_token"),
                ui.tags.pre(f"keys: {list(creds.keys())}"),
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

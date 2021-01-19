//! Downloading utility for pulling files from AppDynamics.
//!
//! This uses their officially documented method for downloading files through
//! their authentication, but in a more automated fashion for use in environments
//! such as CI builds and Docker builds.
//!
//! The documentation was located at the following address in Feb 2020:
//!
//! https://docs.appdynamics.com/display/PRO45/Download+AppDynamics+Software
//!
//! Although this repository was built to aid in Docker builds, you can run this
//! tool manually if you have a Rust compiler.
use bytes::buf::Buf;
use clap::{App, AppSettings, Arg, ArgMatches};
use futures::stream::StreamExt as _;
use hyper::client::HttpConnector;
use hyper::{body, Body, Client, Method, Request, Uri};
use hyper_tls::HttpsConnector;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use std::env;
use std::error::Error;

/// Custom `Result` type which passes back basic errors.
type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Shorthand alias for a HTTPS `Client` instance from Hyper.
type HttpsClient = Client<HttpsConnector<HttpConnector>>;

/// Default endpoint to use for token retrieval from the AppDynamics API.
static DEFAULT_TOKEN_ENDPOINT: &str = "https://identity.msrv.saas.appdynamics.com/v2.0/oauth/token";

/// Default endpoint to use for files listing from the AppDynamics API.
static DEFAULT_FILES_ENDPOINT: &str =
    "https://download.appdynamics.com/download/downloadfilelatest/";

/// Simple model representation for the file structures retrieved
/// in a file listing call against the AppDynamics API.
///
/// This is not complete, rather it only contains the fields we
/// might ever care about internally. Other fields are ignored.
#[derive(Serialize, Deserialize, Debug)]
struct Archive {
    id: usize,

    #[serde(alias = "filename")]
    name: String,

    #[serde(alias = "download_path")]
    path: String,

    #[serde(alias = "creation_time")]
    created: String,
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    // fetch our arguments
    let args = retrieve_arguments();

    // create a new https client instance
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, Body>(https);

    // fetch the token we want to use and the file listing
    let token = retrieve_auth_token(&client, &args).await?;
    let files = retrieve_file_listing(&client, &args).await?;

    // search for the file archive in the list of available files
    let target = args.value_of("indicator").expect("already validated");
    let regexp = Regex::new(&format!("^{}$", target))?;

    // look for an archive
    let archive = files
        .iter()
        .find(|archive| regexp.is_match(&archive.name) || regexp.is_match(&archive.id.to_string()));

    // check we found one
    if archive.is_none() {
        return Err("Unable to locate archive file".into());
    }

    // execute the file download straight to the filesystem
    download_file(&client, &args, &token, &archive.unwrap()).await
}

/// Parses CLI arguments into a set of options we can use.
fn retrieve_arguments<'a>() -> ArgMatches<'a> {
    App::new("")
        .name(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .arg(
            Arg::with_name("indicator")
                .help("A file name or identifier to download")
                .index(1),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .help("Custom output location for the downloaded file")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .help("Account password used for authentication")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("username")
                .short("u")
                .long("username")
                .help("Account username used for authentication")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("auth-endpoint")
                .long("auth-endpoint")
                .help("Custom endpoint to use for authentication")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("files-endpoint")
                .long("files-endpoint")
                .help("Custom endpoint to use for listing available files")
                .takes_value(true)
                .required(false),
        )
        .settings(&[AppSettings::ArgRequiredElseHelp])
        .get_matches()
}

/// Retrieve an authentication token from the AppDynamics token endpoint.
///
/// This will resolve with a token `String` used to sign future API requests.
async fn retrieve_auth_token(client: &HttpsClient, args: &ArgMatches<'_>) -> AnyResult<String> {
    // log for command line visibility to be helpful
    println!("Retrieving authentication token...");

    // unpack the token endpoint provided
    let uri = args.value_of("auth-endpoint");
    let uri = uri.unwrap_or(DEFAULT_TOKEN_ENDPOINT);

    // fetch back the provided credentials
    let username = args.value_of("username").expect("already validated");
    let password = args.value_of("password").expect("already validated");

    // generate a set of credentials used for login
    let credentials = serde_json::to_vec(&json!({
        "username": username,
        "password": password,
        "scopes": [
            "download"
        ]
    }))?;

    // create a request using the credentials
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(credentials))?;

    // execute the request and wait for it
    let res = client.request(req).await?;

    // check for a valid status code
    if res.status() != 200 {
        return Err("Unable to login successfully".into());
    }

    // parse the body back into a Value
    let body = body::aggregate(res).await?;
    let result: Value = serde_json::from_reader(body.reader())?;

    // convert the token value back into a String and resolve the future
    let token_node = result.get("access_token").expect("token always exists");
    let token_value = token_node
        .as_str()
        .expect("token is always a string")
        .to_owned();

    Ok(token_value)
}

/// Retrieve the file listing from the AppDynamics endpoint.
async fn retrieve_file_listing(
    client: &HttpsClient,
    args: &ArgMatches<'_>,
) -> AnyResult<Vec<Archive>> {
    // log for command line visibility to be helpful
    println!("Retrieving available archive listing...");

    // unpack the file listing endpoint provided
    let uri = args.value_of("files-endpoint");
    let uri = uri.unwrap_or(DEFAULT_FILES_ENDPOINT).parse::<Uri>()?;

    // fetch the response from the URI
    let res = client.get(uri).await?;

    // check for a valid status code
    if res.status() != 200 {
        return Err("Unable to retrieve file listing".into());
    }

    // aggregate the body so it's easier to parse
    let body = body::aggregate(res).await?;

    // turn the body back into an archive vec
    Ok(serde_json::from_reader(body.reader())?)
}

/// Downloads an archive file from the AppDynamics API.
///
/// This call requires a signed token for use in calling the API.
async fn download_file(
    client: &HttpsClient,
    args: &ArgMatches<'_>,
    token: &str,
    archive: &Archive,
) -> AnyResult<()> {
    // log for command line visibility to be helpful
    println!("Attempting to resolve location header...");

    // construct a signed request
    let req = Request::builder()
        .method(Method::GET)
        .uri(&archive.path)
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())?;

    // fetch the initial redirection
    let res = client.request(req).await?;

    // fetch the location header
    let headers = res.headers();
    let location = headers.get("location");

    // check for a valid header
    if location.is_none() {
        return Err("Unable to locate redirection header".into());
    }

    // log for command line visibility to be helpful
    let location = location.unwrap().to_str()?.parse::<Uri>()?;
    println!("Attempting to download file from {}", location);

    // then fetch the actual file content
    let mut res = client.get(location).await?;

    // check for a valid status code
    if res.status() != 200 {
        return Err("Unable to download file archive".into());
    }

    // grab the mutable body
    let body = res.body_mut();
    let name = args.value_of("output").unwrap_or(&archive.name);

    // and pipe it through to a local file of the same name
    let mut file = File::create(&name).await?;
    while let Some(v) = body.next().await {
        file.write_all(&v?).await?;
    }

    // sync all remaining data
    file.sync_all().await?;

    // log for command line visibility to be helpful
    println!("{} downloaded successfully!", archive.name);

    Ok(()) // and we're done!
}

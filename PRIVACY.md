# Privacy Policy

**Effective date:** 7 October 2026

This policy covers Strata, the macOS app and the iOS / iPadOS viewer, developed
by Norbert Bonnici.

**The short version:** Strata does not collect personal data. There are no
accounts, analytics, advertising, tracking or third-party crash-reporting
SDKs, and the app sends nothing to the developer.

## iOS / iPadOS viewer

The viewer is a read-only app for opening `.strata` case files built by the
macOS app.

- **It makes no network requests of its own.** Cases are opened from a location
  you choose, such as Files, iCloud Drive or a network share. If you keep cases
  in iCloud Drive, Apple syncs them under your iCloud account and Apple's
  privacy policy.
- **What it stores, on your device only:** a list of recently opened cases, the
  folder you picked as your case library (saved as file bookmarks), and app
  preferences. Deleting the app removes them.

## macOS app

Strata analyses forensic evidence on your Mac. Disk images, extracted
artifacts and case files stay on your Mac, or wherever you choose to save them.
The built-in AI case summary runs on-device with Apple's Foundation Models by
default, so nothing leaves the Mac.

A few optional features connect to outside services. All of them are **off by
default** and only run after you turn them on and supply your own credentials:

- **Threat-intelligence lookups** send indicators from your case (file hashes,
  IP addresses, domains and URLs) to the services you configure: VirusTotal, a
  MISP instance, or an OpenCTI instance.
- **Cloud AI case summary** sends a digest of the case's findings to the
  destination you choose: Apple Private Cloud Compute, Anthropic's API, or
  another endpoint you configure. The digest contains each finding's title,
  severity and a short description, which can include file paths, account
  names and host names from the evidence.

Strata asks for confirmation before it first sends a case summary to a new
destination, and it records each lookup or summary in the case's
chain-of-custody log. Data you send to these services is handled under their
own privacy policies. API keys are stored in the macOS Keychain; they are never
written into case files or sent to the developer.

## TestFlight beta

If you test Strata through TestFlight, Apple collects some information and
shares it with the developer, such as crash reports, install and session
counts, and any feedback or screenshots you choose to send. Apple handles this
under its [privacy policy](https://www.apple.com/legal/privacy/). The developer
uses it only to fix bugs and improve Strata.

## Children

Strata is a professional forensics tool and is not directed at children.

## Changes

Any change to this policy will be published in this file with a new effective
date. Earlier versions remain in the repository's git history.

## Contact

Questions about this policy can be raised as an issue at
<https://github.com/norbertbonnici/Strata/issues>.

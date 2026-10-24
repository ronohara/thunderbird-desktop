# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

openpgp-key-assistant-title = OpenPGP Key Assistant

openpgp-key-assistant-rogue-warning = Avoid accepting a counterfeit key. To ensure you have obtained the right key you should verify it. <a data-l10n-name="openpgp-link">Learn more…</a>

## Encryption status

openpgp-key-assistant-recipients-issue-header = Cannot Encrypt

# Variables:
# $count (Number) - The number of recipients that need attention.
openpgp-key-assistant-recipients-issue-description =
    { $count ->
        [one] To encrypt, you must obtain and accept a usable key for one recipient. <a data-l10n-name="openpgp-link">Learn more…</a>
        *[other] To encrypt, you must obtain and accept usable keys for { $count } recipients. <a data-l10n-name="openpgp-link">Learn more…</a>
    }

openpgp-key-assistant-info-alias = { -brand-short-name } normally requires that the recipient’s public key contains a user ID with a matching email address. This can be overridden by using OpenPGP recipient alias rules. <a data-l10n-name="openpgp-link">Learn more…</a>

# Variables:
# $count (Number) - The number of recipients that need attention.
openpgp-key-assistant-recipients-description =
    { $count ->
        [one] You already have a usable and accepted key for one recipient.
        *[other] You already have usable and accepted keys for { $count } recipients.
    }

openpgp-key-assistant-recipients-description-no-issues = This message can be encrypted. You have usable and accepted keys for all recipients.

## Resolve section

# Variables:
# $recipient (String) - The email address of the recipient needing resolution.
# $numKeys (Number) - The number of keys.
openpgp-key-assistant-resolve-title =
    { $numKeys ->
        [one] { -brand-short-name } found the following key for { $recipient }.
        *[other] { -brand-short-name } found the following keys for { $recipient }.
    }

openpgp-key-assistant-valid-description = Select the key that you want to accept

# Variables:
# $numKeys (Number) - The number of available keys.
openpgp-key-assistant-invalid-title =
    { $numKeys ->
        [one] The following key cannot be used, unless you obtain an update.
        *[other] The following keys cannot be used, unless you obtain an update.
    }

openpgp-key-assistant-no-key-available = No key available.

openpgp-key-assistant-multiple-keys = Multiple keys are available.

# Variables:
# $count (Number) - The number of unaccepted keys.
openpgp-key-assistant-key-unaccepted =
    { $count ->
        [one] A key is available, but it hasn’t been accepted yet.
        *[other] Multiple keys are available, but none of them have been accepted yet.
    }

# Variables:
# $date (String) - The expiration date of the key.
openpgp-key-assistant-key-accepted-expired = An accepted key has expired on { $date }.

openpgp-key-assistant-keys-accepted-expired = Multiple accepted keys have expired.

# Variables:
# $date (String) - The expiration date of the key.
openpgp-key-assistant-this-key-accepted-expired = This key was previously accepted but expired on { $date }.

# Variables:
# $date (String) - The expiration date of the key.
openpgp-key-assistant-key-unaccepted-expired-one =
    The key expired on { $date }.
openpgp-key-assistant-key-unaccepted-expired-many =
    Multiple keys have expired.

openpgp-key-assistant-key-fingerprint = Fingerprint

# Variables:
# $count (Number) - Number of key sources.
openpgp-key-assistant-key-source =
  { $count ->
      [one] Source
      *[other] Sources
  }

openpgp-key-assistant-key-collected-attachment = email attachment
# Autocrypt is the name of a standard.
openpgp-key-assistant-key-collected-autocrypt = Autocrypt header
openpgp-key-assistant-key-collected-keyserver = keyserver
# Web Key Directory (WKD) is a concept.
openpgp-key-assistant-key-collected-wkd = Web Key Directory
# Do not translate GnuPG, it's a name of other software.
openpgp-key-assistant-key-collected-gnupg = GnuPG keyring

# Variables:
# $count (Number) - Number of found keys.
openpgp-key-assistant-keys-has-collected =
  { $count ->
      [one] A key was found, but it hasn’t been accepted yet.
      *[other] Multiple keys were found, but none of them have been accepted yet.
  }

openpgp-key-assistant-key-rejected = This key has been previously rejected.
openpgp-key-assistant-key-accepted-other = This key has been previously accepted for a different email address.

# Variables:
# $recipient (String) - The email address of the recipient needing resolution.
openpgp-key-assistant-resolve-discover-info =
  Discover additional or updated keys for { $recipient } online, or import them from a file.

## Discovery section

openpgp-key-assistant-discover-title = Online discovery in progress.

# Variables:
# $recipient (String) - The email address which we're discovering keys.
openpgp-key-assistant-discover-keys = Discovering keys for { $recipient }…

# Variables:
# $recipient (String) - The email address which we're discovering keys.
openpgp-key-assistant-expired-key-update =
    An update was found for one of the previously accepted keys for { $recipient }.
    It can now be used as it is no longer expired.

## Dialog buttons

openpgp-key-assistant-discover-online-button = Discover Public Keys Online…

openpgp-key-assistant-import-keys-button = Import Public Keys From File…

openpgp-key-assistant-issue-resolve-button = Resolve…

openpgp-key-assistant-view-key-button = View Key…

openpgp-key-assistant-recipients-show-button = Show

openpgp-key-assistant-recipients-hide-button = Hide

openpgp-key-assistant-cancel-button = Cancel

openpgp-key-assistant-back-button = Back

openpgp-key-assistant-accept-button = Accept

openpgp-key-assistant-close-button = Close

openpgp-key-assistant-disable-button = Disable Encryption

openpgp-key-assistant-confirm-button = Send Encrypted

# Variables:
# $date (String) - The key creation date.
openpgp-key-assistant-key-created = created on { $date }

## Signing key

openpgp-key-assistant-signing-key-header = This message will be signed

# Variables:
# $fingerprint (String) - Fingerprint of the key that will sign.
openpgp-key-assistant-signing-key-value = Key { $fingerprint }

# The rule GnuPG used to choose it. Reported rather than assumed, because with
# the external keyring the choice is GnuPG's, not Thunderbird's.
openpgp-key-assistant-signing-key-source-default = Chosen because it is your configured default signing key.
openpgp-key-assistant-signing-key-source-gnupg-order = Chosen by GnuPG: the first usable signing key for this identity.

# The internal engine's rules. Each is reported rather than assumed, for the
# same reason as the two above: the choice has to be visible to be verifiable.
openpgp-key-assistant-signing-key-source-newest-subkey = Chosen automatically: the newest usable signing subkey. The certificate key is not used.
openpgp-key-assistant-signing-key-source-primary = Chosen automatically: the primary key signs, because this key has no usable signing subkey.
openpgp-key-assistant-signing-key-source-named = Chosen by you: a signing subkey is set for this identity. Sending will stop rather than sign with a different key if it cannot be used.

# Variables:
# $fingerprint (String) - Fingerprint of a named subkey that is not in the key.
openpgp-key-assistant-signing-subkey-missing = Key { $fingerprint }, which you chose, is not part of this key any more. Sending will stop until that setting is changed.

# The named choice, matching GnuPG's --local-user / --default-key. Shown only
# for a key the internal engine holds.
openpgp-key-assistant-signing-subkey-label = Signing subkey
openpgp-key-assistant-signing-subkey-automatic = Automatic (newest usable subkey)

# Variables:
# $keyId (String) - Short key ID of the subkey.
# $created (String) - Date the subkey was created.
openpgp-key-assistant-signing-subkey-item = { $keyId } — created { $created }

# Shown under the signing key. Both numbers are read from gpg-agent's own
# configuration; the second is the one that bounds the exposure, because the
# first timer restarts on every use.
#
# Variables:
#   $idle (Number) - minutes gpg-agent keeps a passphrase after it is last used
#   $maximum (Number) - minutes at most, regardless of use
openpgp-key-assistant-passphrase-cached = After you sign, GnuPG keeps your passphrase for { $idle } minutes, or up to { $maximum } minutes if you keep signing. While it is held, any program running as you can use your key without being asked. Tools → Forget GnuPG Passphrases clears it now.

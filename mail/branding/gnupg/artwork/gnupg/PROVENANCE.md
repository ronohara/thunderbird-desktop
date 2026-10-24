PROVENANCE — GnuPG artwork
=========================

Upstream:   git://git.gnupg.org/gnupg.git
Revision:   e660a0e14
Path:       artwork/
Vendored:   2026-10-25, byte-identical to the upstream checkout
Files:      78

Why it is here
--------------

This is GnuPG's own artwork, not a redrawing. The GnuPG message indicator
(design section 14, drawn at the message header's geometry) uses the wing from
artwork/icons/wing.svg — the path and
transform in the embedded copy are identical to the file here — so vendoring
the source keeps the shipped graphic traceable to the file it came from
instead of to a copy somebody made once.

It is also the reason no one has to draw a GnuPG mark for this project.

It is NOT the application mark
------------------------------

The build's application mark — launcher, taskbar, dock, installer, store tile
— is the coiled snake in the directory above, and stays that. Design 11.9.2
gives the reason: an application icon carrying GnuPG's wing says "this
application is GnuPG", which is false; it is Thunderbird with GnuPG as its
keyring. The wing answers "who handled this message?", which is a different
question, and it is used where that question is being asked.

So these files are here for attribution and for the message indicator. They
are not a candidate icon set, and the icon families among them (icons/wing,
icons/lock, icons/lock-wing) must not be promoted to one without reopening
D20 and striking that constraint.

Licences — two of them, and they are not the same
-------------------------------------------------

1. The GnuPG logos
   Copyright (c) 2006 g10 Code GmbH
   GPL v3 or later, OR (at your option) CC-BY-SA 4.0

   Stated in README, which is vendored verbatim and remains the authority.
   This covers gnupg-logo-*, gnupg-favicon-*, gnupg-lock-*, gnupg-badge-* and
   the marks in icons/.

   Note for anyone comparing this with Mozilla's artwork: the MPL that covers
   Mozilla's icons grants no trademark rights, which is why recolouring one is
   a counterfeit risk. GnuPG's artwork is explicitly licensed for reuse. The
   objection to using the wing as the product logo is therefore semantic —
   the mark would say something untrue — and not about permission.

2. The banner fonts
   Bungee:  Copyright 2008 The Bungee Project Authors (david@djr.com)
   Raleway: Copyright (c) 2010-2011 Matt McInerney, Pablo Impallari,
            Rodrigo Fuenzalida
   Both:    SIL Open Font License 1.1

   Stated in banner/Bungee-license.txt and banner/Raleway-license.txt, both
   vendored verbatim. The OFL is not the GPL and is not CC-BY-SA; it governs
   the .ttf files only and carries its own terms for embedding and
   redistribution. Nothing in this project redistributes those fonts at
   present — they are here because they arrived with the banner sources.

Verbatim, unmodified
--------------------

Every file is as upstream shipped it. No file was resized, converted,
optimised or stripped. The icon families are 3:4 in palette mode
(24x32 at the "-32" size, 194x256 at the "-256" size), which Thunderbird's
square 16/22/24/32/48/64/128/256 ladder would require padding and a derived
22 px — another reason not to treat them as a drop-in icon set.

Updating
--------

If upstream changes artwork/, re-copy and re-run the diff. The vendored copy
is expected to be byte-identical; a deliberate local edit should be recorded
here rather than made silently.

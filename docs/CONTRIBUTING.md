# Contributing to Nerva

A good way to help is to test, and report bugs. See
[How to Report Bugs Effectively (by Simon Tatham)](https://www.chiark.greenend.org.uk/~sgtatham/bugs.html)
if you want to help that way. Testing is invaluable in making a piece
of software solid and usable.

## General guidelines

* Comments are encouraged.
* If modifying code for which Doxygen headers exist, that header must be modified to match.
* Tests would be nice to have if you're adding functionality.

Patches are preferably to be sent via a GitHub pull request.

Patches should be self-contained. A good rule of thumb is to have
one patch per separate issue, feature, or logical change. Also, no
other changes, such as random whitespace changes, re-indentation,
or fixing typos, spelling, or wording, unless user visible.
Following the code style of the particular chunk of code you're
modifying is encouraged. Proper squashing should be done (eg, if
you're making a buggy patch, then a later patch to fix the bug,
both patches should be merged).

If you've made random unrelated changes (either because your editor
is annoying or you made them for other reasons), you can select
what changes go into the coming commit using git add -p, which
walks you through all the changes and asks whether or not to
include this particular change. This helps create clean patches
without any irrelevant changes. git diff will show you the changes
in your tree. git diff --cached will show what is currently staged
for commit. As you add hunks with git add -p, those hunks will
"move" from the git diff output to the git diff --cached output,
so you can see clearly what your commit is going to look like.

## Commits and pull requests

Commit messages should be sensible. That means a subject line that
describes the patch, with an optional longer body that gives details,
documentation, etc.

When submitting a pull request on GitHub, make sure your branch is
rebased. No merge commits nor stray commits from other people in
your submitted branch, please. You may be asked to rebase if there
are conflicts (even trivially resolvable ones).

PGP signing commits is strongly encouraged. That should explain why
the previous paragraph is here.

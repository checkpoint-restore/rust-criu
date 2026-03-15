# How to contribute

While bug fixes can first be identified via an "issue", that is not required.
It's ok to just open up a PR with the fix, but make sure you include the same
information you would have included in an issue - like how to reproduce it.

PRs for new features should include some background on what use cases the
new code is trying to address. When possible and when it makes sense, try to
break-up larger PRs into smaller ones - it's easier to review smaller
code changes. But only if those smaller ones make sense as stand-alone PRs.

Regardless of the type of PR, all PRs should include:

* well documented code changes;
* additional testcases, when applicable: ideally, they should fail w/o
  your code change applied;
* documentation changes, when applicable.

Squash your commits into logical pieces of work that might want to be reviewed
separate from the rest of the PRs. Ideally, each commit should implement a
single idea, and the PR branch should pass the tests at every commit. GitHub
makes it easy to review the cumulative effect of many commits; so, when in
doubt, use smaller commits.

This project tries to follow [CRIU's commit message conventions][criu-commit],
although they are not strictly enforced. For general guidance on writing clear
and effective commit messages, see
[How to Write a Git Commit Message][git-commit].

PRs that fix issues should include a reference like `Closes #XXXX` in the
commit message so that github will automatically close the referenced issue
when the PR is merged.

Contributors must assert that they are in compliance with the [Developer
Certificate of Origin 1.1](http://developercertificate.org/). This is achieved
by adding a "Signed-off-by" line containing the contributor's name and e-mail
to every commit message. Your signature certifies that you wrote the patch or
otherwise have the right to pass it on as an open-source patch.

The use of AI tools is welcome but should be correctly attributed, especially
for substantial changes. You can use one of the following in your commit
message:

* `Assisted-by: <AI tool>`
* `Co-authored-by: <AI tool>`
* `Generated-by: <AI tool>`
* Or mention it in the commit message body, e.g., "Generated with \<AI tool\>"

Marking AI-assisted contributions helps preserve both legal clarity and
community trust, and makes it easier for reviewers to evaluate the code
in context. For more information, see [AI-assisted development and open source:
Navigating the legal issues][ai-legal].

## Code quality

Before submitting a PR, please make sure your changes pass the following
checks locally:

* `cargo fmt --all -- --check` — ensure consistent code formatting;
* `cargo clippy --all-targets --all-features -- -D warnings` — catch
  common mistakes and non-idiomatic code;
* `cargo build` — verify the project compiles without errors.

These checks are also enforced by CI on every pull request.

[ai-legal]: https://www.redhat.com/en/blog/ai-assisted-development-and-open-source-navigating-legal-issues
[criu-commit]: https://github.com/checkpoint-restore/criu/blob/criu-dev/CONTRIBUTING.md
[git-commit]: https://chris.beams.io/posts/git-commit/

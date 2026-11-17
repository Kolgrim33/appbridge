# Draft: Why converting a .deb to an Arch package needs more than `ar x`

> Note: this is an outline with the facts filled in. Rewrite it in your own words before publishing.
> This Week in Rust and most communities prefer articles written by a human, and your own story will land better.

## Hook (2-3 sentences)

I wanted to install an Ubuntu `.deb` on Arch. Tools exist that unpack it and repack it, but none told me
up front whether the result would actually work. So I built AppBridge to answer that first.

## Section 1: The problem with blind repackaging

- A `.deb` is an `ar` archive holding `control.tar.*` and `data.tar.*`.
- Unpacking and repacking is easy. Knowing it will work is hard.
- Three things usually break: dependency names, shared libraries, and install scripts.

## Section 2: What AppBridge checks before converting

1. **Dependency names.** Debian says `libgtk-3-0`, Arch says `gtk3`. Version syntax differs too
   (`>= 1:2.34-0ubuntu3` becomes `>=2.34`). Alternatives like `a | b` need a choice.
2. **Shared libraries.** It reads the ELF `DT_NEEDED` entries (using the `goblin` crate) and checks them
   against what the target system provides.
3. **Maintainer scripts.** `postinst` can run arbitrary code as root. AppBridge accepts a small set of
   known-safe actions such as `ldconfig` and refuses everything else.

The result is one of three labels: `SAFE_TO_CONVERT`, `CONVERT_WITH_WARNINGS`, `UNSUPPORTED`.

## Section 3: Proving it works

- CI runs the generated package through real `pacman -U` inside an Arch Linux container.
- Show the real output from `appbridge convert` (copy it from your terminal).

## Section 4: Running Windows apps is a different problem

- Converting a package and running a foreign binary are not the same thing, so AppBridge keeps them as
  two separate steps: `create_conversion_plan` and `create_run_plan`.
- Windows apps run through Wine. Before that, AppBridge reads the PE imports and checks for kernel-level
  anti-cheat, which Wine cannot support.

## Section 5: What I learned / what is next

- Tell the honest story: what was harder than expected (for example cross-platform CI on Windows and macOS).
- Link the repo, the `good first issue` list, and ask for feedback.

## Where to publish

dev.to, Hashnode, or your own blog. Add the demo from the README and link https://github.com/Kolgrim33/appbridge.

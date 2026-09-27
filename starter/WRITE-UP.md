# Where the write-up is

`BUILD-LOG.md` and `DECISIONS.md` live at the **repository root**, one level up from this
folder, as the submission instructions require. They started here, where the templates shipped,
and were moved with `git mv`, so their full history is still there:

```sh
git log --follow --format='%h %ad %s' -- BUILD-LOG.md
git log --follow --format='%h %ad %s' -- DECISIONS.md
```

SUBDIR = cmdline delta deltify idset path fetch tog secrets

.if make(clean) || make(obj)
SUBDIR += gotd gotwebd gotsysd
.endif

.include <bsd.subdir.mk>

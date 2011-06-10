# Nothing here is built or distributed by default.

all: serpent-sbox3.pdf serpent-sbox4.pdf serpent-sbox5.pdf

%.pdf: %.dot
	dot -Tpdf $< -o $@

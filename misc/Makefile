# Nothing here is built or distributed by default.

all: serpent-sbox3.pdf serpent-sbox4.pdf serpent-sbox5.pdf \
	serpent-sbox6.pdf serpent-sbox7.pdf

%.pdf: %.dot
	dot -Tpdf $< -o $@

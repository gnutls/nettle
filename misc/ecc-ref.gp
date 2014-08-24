/* Script for pari/gp. Run as gp -q ecc-ref.gp */

out(apriv, A, bpriv, B, S) = print(	\
  "/* a_s */ \"", apriv, "\",\n",	\
  "/* a_x */ \"", component(A[1], 2), "\",\n",	\
  "/* a_y */ \"", component(A[2], 2), "\",\n",	\
  "/* b_s */ \"", bpriv, "\",\n",			\
  "/* b_x */ \"", component(B[1], 2), "\",\n",	\
  "/* b_y */ \"", component(B[2], 2), "\",\n",	\
  "/* s_x */ \"", component(S[1], 2), "\",\n",	\
  "/* s_y */ \"", component(S[2], 2), "\",");
				   
p192 = 2^192 - 2^64 - 1;
b192 = 2455155546008943817740293915197451784769108058161191238065;
g192 = Mod([602046282375688656758213480587526111916698976636884684818, \
	    174050332293622031404857552280219410364023488927386650641], p192);
secp192 = ellinit(Mod([0,0,0,-3, b192], p192));
q192 = 6277101735386680763835789423176059013767194773182842284081;
if (ellorder(secp192, g192) != q192, error("secp192 parameter error"));

a192 = 1+random(q192-1);
b192 = 1+random(q192-1);
A192 = ellpow(secp192, g192, a192);
B192 = ellpow(secp192, g192, b192);
S192 = ellpow(secp192, A192, b192);
if (S192 != ellpow(secp192, B192, a192), error("secp192 dh error"));
print("secp192");
out(a192, A192, b192, B192, S192);

quit

/* sexp-conv.c
 *
 * Conversion tool for handling the different flavours of sexp
 * syntax. */

#include "base64.h"

enum sexp_mode
  {
    SEXP_CANONICAL = 0,
    SEXP_ADVANCED = 1,
    /* OR:ed with SEXP_CANONICAL or SEXP_ADVANCED when reading
     * transport data. */
    SEXP_TRANSPORT = 2,
  };

enum sexp_token
  {
    SEXP_LIST,
    SEXP_STRING,
    SEXP_DISPLAY_START,
    SEXP_DISPLAY_END,
    SEXP_LIST_START,
    SEXP_LIST_END,
    SEXP_TRANSPORT_START,
    SEXP_TRANSPORT_END,
    SEXP_EOF,
  };

struct sexp_input
{
  FILE *f;
  
  enum sexp_mode mode;
  /* Used in transport mode */
  struct base64_decode_ctx base64;

  /* Type of current token */
  enum sexp_token token;

  /* Current token */
  struct nettle_buffer string;

  /* Nesting level */
  unsigned level;
};

struct sexp_output
{
  FILE *f;

  enum sexp_mode mode;

  unsigned indent;
  unsigned pos;
};

	  
/* Returns 1 on success. On failure, return -1. For special tokens,
 * return 0 and set input->token accordingly. */
static int
sexp_get_char(struct sexp_input *input, uint8_t *out)
{
  if (input->mode & SEXP_TRANSPORT)
    {
      /* Base64 decode */
      for (;;)
	{
	  int done;
	  int c = getc(input->f);
	  if (c < 0)
	    return -1;

	  if (c == '}')
	    {
	      if (base64_decode_status(&input->ctx))
		{
		  input->token = SEXP_TRANSPORT_END;
		  return 0;
		}
	      else
		return -1;
	    }

	  done = base64_decode_single(&input->ctx, out, c);
	  if (done)
	    return 1;
	}
    }
  else
    for (;;)
      {
	int c = getc(input->f);
      
	if (c < 0)
	  {
	    if (ferror(input->f))
	      return -1;
	    
	    input->token = SEXP_EOF;
	    return 0;
	  }
      }
}

static const char
token_chars[0x80] =
  {
    /* 0, ... 0x1f */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* SPC ! " # $ % & '  ( ) * + , - . / */
    0,0,0,0,0,0,0,0, 0,0,1,1,0,1,1,1,
    /* 0 1 2 3 4 5 6 7  8 9 : ; < = > ? */
    1,1,1,1,1,1,1,1, 1,1,1,0,0,1,0,0,
    /* @ A ... O */
    0,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,	
    /* P ...             Z [ \ ] ^ _ */
    1,1,1,1,1,1,1,1, 1,1,1,0,0,0,0,1,
    /* ` a, ... o */
    0,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,	
    /* p ...             z { | } ~ DEL */
    1,1,1,1,1,1,1,1, 1,1,1,0,0,0,0,0,
  };

#define TOKEN_CHAR(c) ((c) < 0x80 && token_chars[(c)])

/* Returns 0 at end of token */
static uint8_t
sexp_get_token_char(struct sexp_input *input)
{
  int c = getc(input->f);
  if (c >= 0 && TOKEN_CHAR(c))
    return c;

  ungetc(input->f, c);
  return 0;
}
     

#if 0
static void
sexp_unget_char(struct sexp_input *input, uint8_t c)
{
  assert(input->mode == SEXP_ADVANCED);
  ungetc(c, input->f);
}
#endif

static int
sexp_get_string_char(struct sexp_input *input)
{
  assert(input->mode == SEXP_ADVANCED);
  
}

static int
sexp_get_quoted_char(struct sexp_input *input, uint8_t *c)
{
  if (sexp_get_char(input, c) <= 0)
    return -1;

  for (;;)
    switch (*c)
      {
      case '\"':
	return 0;
      case '\\':
	if (sexp_get_char(input, c) <= 0)
	  return -1;
	switch (*c)
	  {
	  case 'b': *c = '\b'; return 1;
	  case 't': *c = '\t'; return 1;
	  case 'n': *c = '\n'; return 1;
	  case 'f': *c = '\f'; return 1;
	  case 'r': *c = '\r'; return 1;
	  case '\\': *c = '\\'; return 1;
	  case 'o':
	  case 'x':
	    /* Not implemnted */
	    abort();
	  case '\n':
	    if (sexp_get_char(input, c) <= 0)
	      return -1;
	    if (*c == '\r' && sexp_get_char(input, c) <= 0)
	      return -1;
	    break;
	  case '\r':
	    if (sexp_get_char(input, c) <= 0)
	      return -1;
	    if (*c == '\n' && sexp_get_char(input, c) <= 0)
	      return -1;
	    break;
	  }
      }
}

static int
sexp_get_quoted_string(struct sexp_input *input)
{
  assert(input->mode == SEXP_ADVANCED);
  
  for (;;)
    {
      uint8_t c;
      
      switch (sexp_get_quoted_char(input, &c))
	{
	case 0:
	  return 1;
	case -1:
	  return 0;
	default:
	  if (!NETTLE_BUFFER_PUTC(&input->string, c))
	    return 0;
	}
    }
}

static int
sexp_get_hex_string(struct sexp_input *input)
{
  /* Not implemented */
  abort();
}

static int
sexp_get_base64_string(struct sexp_input *input)
{
  struct base64_decode_ctx ctx;

  assert(input->mode == SEXP_ADVANCED);

  base64_decode_init(&ctx);
  
  for (;;)
    {
      uint8_t c;
      uint8_t decoded;
      
      if (sexp_get_char(input, &c) <= 0)
	return -1;

      if (c == '|')
	return base64_decode_status(&ctx);
      
      if (base64_decode_single(&ctx, &decoded, c))
	if (!NETTLE_BUFFER_PUTC(&input->string, decoded))
	  return 0;
    }
}

static int
sexp_get_atom_string(struct sexp_input *input, uint8_t c)
{
  assert(input->mode == SEXP_ADVANCED);

  if (!TOKEN_CHAR(c) || ! NETTLE_BUFFER_PUTC(&input->string, c))
    return 0;
  
  while ( (c = sexp_get_token_char(input)) > 0)
    {
      if (!NETTLE_BUFFER_PUTC(&input->string, c))
	return 0;
    }

  assert (input->string.size);
  return 1;
}

static int
sexp_get_string(struct sexp_input *input, uint8_t c)
{
  assert(input->mode == SEXP_ADVANCED);
  input->string.size = 0;
  input->token = SEXP_STRING;
  
  switch (c)
    {
    case '\"':
      return sexp_get_quoted_string(input);

    case '#':
      return sexp_get_hex_string(input);

    case '|':
      return sexp_get_base64_string(input);

    default:
      return sexp_get_token_string(input, c);
    }
}

static int
sexp_get_string_length(struct sexp_input *input, unsigned length)
{
  uint8_t c;
	
  input->string.size = 0;
  input->token = SEXP_STRING;
  
  if (!length)
    {
      /* There must ne no more digits */
      if (sexp_get_char(input, &c) <= 0)
	return 0;
    }
  else
    /* Get rest of digits */
    for (;;)
      {
	if (sexp_get_char(input, &c) <= 0)
	  return 0;

	if (c < 0 || < > 9)
	  break;
	
	/* FIXME: Check for overflow? */
	length = length * 10 + c - '0';
      }

  switch(c)
    {
    case ':':
      /* Verbatim */
      for (; length; length--)
	if (sexp_get_char(input, &c) <= 0
	    || !NETTLE_BUFFER_PUTC(&input->string, c))
	  return 0;
      
      return 1;

    case '"':
      if (input->mode != SEXP_ADVANCED)
	return 0;

      for (; length; length--)
	if (sexp_get_quoted_char(input, &c) != 1
	    || !NETTLE_BUFFER_PUTC(&input->string, c))
	  return 0;

      return sexp_get_quoted_char(input, &c) == 0;
      
    case '#':
    case '|':
      /* Not yet implemented */
      abort();

    default:
      return 0;
    }
}

/* Returns 1 on success, zero on failure */
static int
sexp_get_token(struct sexp_input *input)
{
  uint8_t c;
  switch (sexp_get_char(input, &c))
    {
    case -1:
      return 0;
    case 0:
      return 1;
    case 1:
      switch(c)
	{
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	  return sexp_get_string_length(input, c - '0');
	  
	case '(':
	  input->token = SEXP_START_LIST;
	  return 1;
	case ')':
	  input->token = SEXP_END_LIST;
	  return 1;

	case '[':
	  input->token = SEXP_DISPLAY_START;
	  return 1;

	case ']':
	  input->token = SEXP_DISPLAY_END;
	  return 1;

	case ' ':  /* SPC, TAB, LF, CR */
	case '\t':
	case '\n':
	case '\r':
	  if (input->mode != SEXP_ADVANCED)
	    return 0;
	  break;

	case ';': /* Comments */
	  if (input->mode != SEXP_ADVANCED)
	    return 0;

	  for (;;)
	    {
	      int c = getc(input->f);
	      if (c < 0)
		{
		  if (ferror(input->f))
		    return 0;
		  else
		    {
		      input->token = SEXP_EOF;
		      return 1;
		    }
		}
	      if (c != '\n')
		break;
	    }
	  break;
	  
	default:
	  /* Ought to be a string */
	  return (input->mode == SEXP_ADVANCED)
	    && sexp_get_string(input, c);
	}
    }  
}

static int
sexp_put_newline(struct sexp_output *output)
{
  unsigned i;
  if (putc('\n', output->f) < 0)
    return 0;

  for(i = 0; i<output->indent)
    if (putc(' ', output->f) < 0)
      return 0;

  output->pos = output->indent;

  return 1;
}

static int
sexp_put_char(struct sexp_output *output,
	      uint8_t c)
{
  output->pos++;
  return fputc(c, output->file) >= 0;
}

static int
sexp_put_data(struct sexp_output *output,
	      unsigned length, uint8_t data)
{
  if (fwrite(data, 1, length, output->f)
      == length)
    {
      output->pos += length;
      return 1;
    }
  else
    return 0;
}


static int
sexp_put_string(struct sexp_output *output,
		struct nettle_buffer *string)
{
  if (!string->size)
    {
      const char *s = (output->mode == SEXP_ADVANCED) ? "\"\"": "0:";
      output->pos += 2;

      return 2 == fputs(s , output->f);
    }
  
  if (output->mode == SEXP_ADVANCED)
    {
      unsigned i;
      int token = (string.buffer[0] < '0' || string.buffer[0] > '9');
      int quote_friendly = 1;
      
      for (i = 0; i<string.size; i++)
	{
	  uint8_t c = string.buffer[i];
	  
	  if (token & !TOKEN_CHAR(c))
	    token = 0;
	  
	  if (quote_friendly && (c < 0x20 || c >= 0x7f))
	    quote_friendly = 0;
	}
      
      if (token)
	return sexp_put_buffer(output, string.size, string.buffer);

      else if (quote_friendly)
	{
	  output->pos += 2;
	  
	  return sexp_put_char(output, '"')
	    && sexp_put_buffer(output, string.size, string.buffer)
	    && sexp_put_char(output, '"');
	}
      else
	{
#define DATA_PER_LINE 40
	  uint8_t line[BASE64_ENCODE_LENGTH(DATA_PER_LINE)
		       + BASE64_ENCODE_FINAL_LENGTH];
	  struct base64_encode_ctx ctx;

	  unsigned old_indent = output->indent;
	  unsigned i;
	  
	  output->indent = output->pos + 1;
	  if (!sexp_put_char(output, '|'))
	    return 0;
	  
	  base64_encode_init(&ctx);
	  for (i = 0; i + DATA_PER_LINE < string.size)
	    {
	      unsigned done = base64_encode_update(&ctx,
						   line,
						   DATA_PER_LINE,
						   string->buffer + i);

	      assert(done <= BASE64_ENCODE_LENGTH(DATA_PER_LINE));
	      
	      sexp_put_data(output, done, line);
	      sexp_put_newline(output);
	    }

	  output->indent = old_indent;
	  
	  done = base64_encode_update(&ctx, line,
				      string.size - i, string->buffer  + i);
	  done += base64_encode_final(&ctx, line + done);
	  assert(done <= sizeof(line));

	  return sexp_put_data(output, done, line)
	    && sexp_put_char(output, '}');
	}
    }
  else
    /* FIXME: Support transport mode */
    return fprintf(output->f, "%d:", string.length) > 0
      && sexp_put_string(output, string.size, string.buffer);
}

static void
sexp_put_start_list(struct sexp_output *output)
{
}



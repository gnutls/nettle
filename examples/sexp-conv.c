/* sexp-conv.c
 *
 * Conversion tool for handling the different flavours of sexp
 * syntax. */

#include "base64.h"
#include "buffer.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
die(const char *format, ...)
#if __GNUC___
     __attribute__((__format__ (__printf__,1, 2)))
     __attribute__((__noreturn__))
#endif
     ;

void
die(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  exit(EXIT_FAILURE);
}

enum sexp_mode
  {
    SEXP_CANONICAL = 0,
    SEXP_ADVANCED = 1,
    /* OR:ed with SEXP_CANONICAL or SEXP_ADVANCED when reading
     * transport data */
    SEXP_TRANSPORT = 2,
  };

enum sexp_token
  {
    SEXP_STRING,
    SEXP_DISPLAY_START,
    SEXP_DISPLAY_END,
    SEXP_LIST_START,
    SEXP_LIST_END,
    SEXP_TRANSPORT_START,
    SEXP_TRANSPORT_END,
    SEXP_EOF,
  };

enum sexp_coding
  {
    SEXP_PLAIN,
    SEXP_BASE64,
    SEXP_HEX,
  };
    
struct sexp_input
{
  FILE *f;
  
  enum sexp_coding coding;
  /* Used in transport mode */
  struct base64_decode_ctx base64;

  /* Type of current token */
  enum sexp_token token;

  /* Current token */
  struct nettle_buffer string;

  /* Nesting level */
  unsigned level;
};

static void
sexp_input_init(struct sexp_input *input, FILE *f)
{
  input->f = f;
  input->coding = SEXP_PLAIN;
  input->level = 0;

  nettle_buffer_init(&input->string);
}

struct sexp_output
{
  FILE *f;

  enum sexp_mode mode;
  struct base64_encode_ctx base64;

  unsigned pos;
};

static void
sexp_output_init(struct sexp_output *output, FILE *f, enum sexp_mode mode)
{
  output->f = f;
  output->mode = mode;
  output->pos = 0;
}


/* Input */

/* Returns 1 on success. For special tokens,
 * return 0 and set input->token accordingly. */
static int
sexp_get_char(struct sexp_input *input, uint8_t *out)
{
  switch (input->coding)
    {
    case SEXP_BASE64:
      for (;;)
	{
	  int done;
	  int c = getc(input->f);
	  if (c < 0)
	    die("Unexpected end of file in base64 data.\n");

	  if (c == '}')
	    {
	      if (base64_decode_status(&input->base64))
		{
		  input->token = SEXP_TRANSPORT_END;
		  return 0;
		}
	      else
		die("Invalid base64 data.\n");
	    }

	  done = base64_decode_single(&input->base64, out, c);
	  if (done)
	    return 1;
	}
    case SEXP_PLAIN:
      {
	int c = getc(input->f);
      
	if (c < 0)
	  {
	    if (ferror(input->f))
	      die("Read error: %s\n", strerror(errno));
	  
	    input->token = SEXP_EOF;
	    return 0;
	  }

	*out = c;
	return 1;
      }
    case SEXP_HEX:
      /* Not yet implemented */
      abort();
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

  ungetc(c, input->f);
  return 0;
}
     
/* Return 0 at end-of-string */
static int
sexp_get_quoted_char(struct sexp_input *input, uint8_t *c)
{
  if (!sexp_get_char(input, c))
    die("Unexpected end of file in quoted string.\n");

  for (;;)
    switch (*c)
      {
      default:
	return 1;
      case '\"':
	return 0;
      case '\\':
	if (!sexp_get_char(input, c))
	  die("Unexpected end of file in quoted string.\n");

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
	    if (!sexp_get_char(input, c))
	      die("Unexpected end of file in quoted string.\n");
	    if (*c == '\r' && !sexp_get_char(input, c))
	      die("Unexpected end of file in quoted string.\n");
	    break;
	  case '\r':
	    if (!sexp_get_char(input, c))
	      die("Unexpected end of file in quoted string.\n");
	    if (*c == '\n' && !sexp_get_char(input, c))
	      die("Unexpected end of file in quoted string.\n");
	    break;
	  }
      }
}

static void
sexp_get_quoted_string(struct sexp_input *input)
{
  uint8_t c;

  assert(input->coding == SEXP_PLAIN);
  
  while (sexp_get_quoted_char(input, &c))
    if (!NETTLE_BUFFER_PUTC(&input->string, c))
      die("Virtual memory exhasuted.\n");
}

static void
sexp_get_hex_string(struct sexp_input *input)
{
  /* Not implemented */
  abort();
}

static void
sexp_get_base64_string(struct sexp_input *input)
{
  struct base64_decode_ctx ctx;

  assert(input->coding == SEXP_PLAIN);

  base64_decode_init(&ctx);
  
  for (;;)
    {
      uint8_t c;
      uint8_t decoded;
      
      if (!sexp_get_char(input, &c))
	die("Unexpected end of file in base64 string.\n");

      if (c == '|')
	{
	  if (!base64_decode_status(&ctx))
	    die("Invalid base64 string.\n");
	  return;
	}
      
      if (base64_decode_single(&ctx, &decoded, c)
	  && !NETTLE_BUFFER_PUTC(&input->string, decoded))
	die("Virtual memory exhasuted.\n");	
    }
}

static void
sexp_get_token_string(struct sexp_input *input, uint8_t c)
{
  assert(input->coding == SEXP_PLAIN);

  if (!TOKEN_CHAR(c) || ! NETTLE_BUFFER_PUTC(&input->string, c))
    die("Invalid token.\n");
  
  while ( (c = sexp_get_token_char(input)) > 0)
    {
      if (!NETTLE_BUFFER_PUTC(&input->string, c))
	die("Virtual memory exhasuted.\n");	
    }

  assert (input->string.size);
}

static void
sexp_get_string(struct sexp_input *input, uint8_t c)
{
  input->string.size = 0;
  input->token = SEXP_STRING;
  
  switch (c)
    {
    case '\"':
      sexp_get_quoted_string(input);
      break;
      
    case '#':
      sexp_get_hex_string(input);
      break;;

    case '|':
      sexp_get_base64_string(input);
      break;

    default:
      sexp_get_token_string(input, c);
      break;
    }
}

static void
sexp_get_string_length(struct sexp_input *input, enum sexp_mode mode,
		       unsigned length)
{
  uint8_t c;
	
  input->string.size = 0;
  input->token = SEXP_STRING;
  
  if (!length)
    {
      /* There must ne no more digits */
      if (!sexp_get_char(input, &c))
	die("Unexpected end of file in string.\n");
    }
  else
    /* Get rest of digits */
    for (;;)
      {
	if (!sexp_get_char(input, &c))
	  die("Unexpected end of file in string.\n");

	if (c < '0' || c > '9')
	  break;
	
	/* FIXME: Check for overflow? */
	length = length * 10 + c - '0';
      }

  switch(c)
    {
    case ':':
      /* Verbatim */
      for (; length; length--)
	if (!sexp_get_char(input, &c)
	    || !NETTLE_BUFFER_PUTC(&input->string, c))
	  die("Unexpected end of file in string.\n");
      
      return;

    case '"':
      if (mode != SEXP_ADVANCED)
	die("Encountered quoted string in canonical mode.\n");

      for (; length; length--)
	if (!sexp_get_quoted_char(input, &c)
	    || !NETTLE_BUFFER_PUTC(&input->string, c))
	  die("Unexpected end of string.\n");

      if (sexp_get_quoted_char(input, &c))
	die("Quoted string longer than expected.\n");
      
    case '#':
    case '|':
      /* Not yet implemented */
      abort();

    default:
      die("Invalid string.\n");
    }
}

static void
sexp_get_token(struct sexp_input *input, enum sexp_mode mode)
{
  uint8_t c;

  for(;;)
    if (!sexp_get_char(input, &c))
      return;
    else
      switch(c)
	{
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	  sexp_get_string_length(input, mode, c - '0');
	  return;
	  
	case '(':
	  input->token = SEXP_LIST_START;
	  return;
	  
	case ')':
	  input->token = SEXP_LIST_END;
	  return;

	case '[':
	  input->token = SEXP_DISPLAY_START;
	  return;

	case ']':
	  input->token = SEXP_DISPLAY_END;
	  return;

	case ' ':  /* SPC, TAB, LF, CR */
	case '\t':
	case '\n':
	case '\r':
	  if (mode == SEXP_CANONICAL)
	    die("Whitespace encountered in canonical mode.\n");
	  break;

	case ';': /* Comments */
	  if (mode == SEXP_CANONICAL)
	    die("Comment encountered in canonical mode.\n");

	  for (;;)
	    {
	      int c = getc(input->f);
	      if (c < 0)
		{
		  if (ferror(input->f))
		    die("Read failed: %s.\n", strerror(errno));
		  else
		    {
		      input->token = SEXP_EOF;
		      return;
		    }
		}
	      if (c == '\n')
		break;
	    }
	  break;
	  
	default:
	  /* Ought to be a string */
	  if (mode != SEXP_ADVANCED)
	    die("Encountered advanced string in canonical mode.\n");

	  sexp_get_string(input, c);
	  return;
	}
}



/* Output routines */

#define LINE_WIDTH 60

static void 
sexp_put_newline(struct sexp_output *output,
		 unsigned indent)
{
  unsigned i;
  if (putc('\n', output->f) < 0)
    die("Write failed: %s\n", strerror(errno));

  for(i = 0; i < indent; i++)
    if (putc(' ', output->f) < 0)
      die("Write failed: %s\n", strerror(errno));

  output->pos = indent;
}

static void
sexp_put_char(struct sexp_output *output, unsigned indent,
	      uint8_t c)
{
  if (output->mode & SEXP_TRANSPORT)
    {
      uint8_t encoded[2];
      unsigned done;
      unsigned i;
      
      done = base64_encode_single(&output->base64, encoded, c);

      assert(done <= sizeof(encoded));

      for (i = 0; i<done; i++)
	{
	  if (indent &&
	      output->pos > LINE_WIDTH
	      && output->pos > (indent + 10))
	    sexp_put_newline(output, indent);
	  
	  if (putc(encoded[i], output->f) < 0)
	    die("Write failed: %s\n", strerror(errno));

	  output->pos++;
	}
    }
  else
    {
      output->pos++;
      if (putc(c, output->f) < 0)
	die("Write failed: %s\n", strerror(errno));
    }
}

static void
sexp_put_data(struct sexp_output *output, unsigned indent,
	      unsigned length, const uint8_t *data)
{
  unsigned i;

  for (i = 0; i<length; i++)
    sexp_put_char(output, indent, data[i]);
}

static void
sexp_puts(struct sexp_output *output, unsigned indent,
	  const uint8_t *s)
{
  while (*s)
    sexp_put_char(output, indent, *s++);
}

static void
sexp_put_length(struct sexp_output *output, unsigned indent,
		unsigned length)
{
  unsigned digit = 1;

  while (digit < length)
    digit *= 10;

  for (; digit; length %= digit, digit /= 10)
    sexp_put_char(output, indent, '0' + length / digit);
}

static void
sexp_put_base64_start(struct sexp_output *output, uint8_t c)
{
  assert(! (output->mode & SEXP_TRANSPORT));
  
  sexp_put_char(output, 0, c);

  base64_encode_init(&output->base64);
  output->mode |= SEXP_TRANSPORT;
}

static void
sexp_put_base64_end(struct sexp_output *output, uint8_t c)
{
  uint8_t encoded[BASE64_ENCODE_FINAL_LENGTH];
  unsigned done;

  assert(output->mode & SEXP_TRANSPORT);

  done = base64_encode_final(&output->base64, encoded);

  assert(done <= sizeof(encoded));
  
  output->mode &= ~ SEXP_TRANSPORT;

  sexp_put_data(output, 0, done, encoded);
  sexp_put_char(output, 0, c);
}

static void
sexp_put_string(struct sexp_output *output, unsigned indent,
		struct nettle_buffer *string)
{
  if (!string->size)
    sexp_puts(output, indent,
	      (output->mode == SEXP_ADVANCED) ? "\"\"": "0:");

  else if (output->mode == SEXP_ADVANCED)
    {
      unsigned i;
      int token = (string->contents[0] < '0' || string->contents[0] > '9');
      int quote_friendly = 1;
      static const char escape_names[0x10] =
	{ 0,0,0,0,0,0,0,0, 'b','t','n',0,'f','r',0,0 };

      for (i = 0; i<string->size; i++)
	{
	  uint8_t c = string->contents[i];
	  
	  if (token & !TOKEN_CHAR(c))
	    token = 0;
	  
	  if (quote_friendly)
	    {
	      if (c >= 0x7f)
		quote_friendly = 0;
	      else if (c < 0x20 && !escape_names[c])
		quote_friendly = 0;
	    }
	}
      
      if (token)
	sexp_put_data(output, indent, string->size, string->contents);

      else if (quote_friendly)
	{
	  sexp_put_char(output, indent, '"');

	  for (i = 0; i<string->size; i++)
	    {
	      int escape = 0;
	      uint8_t c = string->contents[i];

	      assert(c < 0x7f);
	      
	      if (c == '\\' || c == '"')
		escape = 1;
	      else if (c < 0x20)
		{
		  escape = 1;
		  c = escape_names[c];
		  assert(c);
		}
	      if (escape)
		sexp_put_char(output, indent, '\\');

	      sexp_put_char(output, indent, c);
	    }
	  
	  sexp_put_char(output, indent, '"');
	}
      else
	{
	  sexp_put_base64_start(output, '|');
	  sexp_put_data(output, output->pos,
			string->size, string->contents);
	  sexp_put_base64_end(output, '|');
	}
    }
  else
    {
      sexp_put_length(output, indent, string->size);
      sexp_put_char(output, indent, ':');
      sexp_put_data(output, indent, string->size, string->contents);
    }
}

static void
sexp_put_list_start(struct sexp_output *output, unsigned indent)
{
  sexp_put_char(output, indent, '(');
}

static void
sexp_put_list_end(struct sexp_output *output, unsigned indent)
{
  sexp_put_char(output, indent, ')');
}

static void
sexp_put_display_start(struct sexp_output *output, unsigned indent)
{
  sexp_put_char(output, indent, '[');
}

static void
sexp_put_display_end(struct sexp_output *output, unsigned indent)
{
  sexp_put_char(output, indent, ']');
}

static void
sexp_convert_string(struct sexp_input *input, enum sexp_mode mode,
		    struct sexp_output *output, unsigned indent)
{
  sexp_get_token(input, mode);
  if (input->token == SEXP_STRING)
    sexp_put_string(output, indent, &input->string);
  else
    die("Invalid string.\n");
}

static int
sexp_convert_item(struct sexp_input *input, enum sexp_mode mode,
		  struct sexp_output *output, unsigned indent);

static void
sexp_convert_list(struct sexp_input *input, enum sexp_mode mode,
		  struct sexp_output *output,
		  unsigned indent)
{
  unsigned item;

  for (item = 0;; item++)
    {
      sexp_get_token(input, mode);
  
      /* Check for end of list */
      if (input->token == SEXP_LIST_END
	  || input->token == SEXP_EOF
	  || input->token == SEXP_TRANSPORT_END)
	return;

      if (output->mode == SEXP_ADVANCED)
	{
	  /* FIXME: Adapt pretty printing to handle a big first
	   * element. */
	  if (item == 1)
	    {
	      sexp_put_char(output, indent, ' ');
	      indent = output->pos;
	    }
	  else if (item > 1)
	    sexp_put_newline(output, indent);
	}
      
      if (!sexp_convert_item(input, mode, output, indent))
	/* Should be detected above */
	abort();
    }
}

static void
sexp_convert_file(struct sexp_input *input, struct sexp_output *output)
{
  sexp_get_token(input, SEXP_ADVANCED);

  while (input->token != SEXP_EOF)
    {
      sexp_convert_item(input, SEXP_ADVANCED, output, 0);
      if (output->mode == SEXP_ADVANCED)
	sexp_put_newline(output, 0);
	  
      sexp_get_token(input, SEXP_ADVANCED);
    }

  if (fflush(output->f) < 0)
    die("Final fflush failed: %s.\n", strerror(errno));
}



static void
sexp_skip_token(struct sexp_input *input, enum sexp_mode mode,
		enum sexp_token token)
{
  sexp_get_token(input, mode);
  if (input->token != token)
    die("Syntax error.\n");
}

/* Returns 1 on success  and 0 at end of list/file.
 *
 * Should be called after getting the first token. */
static int
sexp_convert_item(struct sexp_input *input, enum sexp_mode mode,
		  struct sexp_output *output, unsigned indent)
{
  switch(input->token)
    {
    case SEXP_LIST_START:
      input->level++;
      
      sexp_put_list_start(output, indent);
      sexp_convert_list(input, mode, output, indent);
      sexp_put_list_end(output, indent);

      if (input->level)
	{
	  input->level--;
	  if (input->token == SEXP_LIST_END)
	    break;
	}
      else if (input->token == SEXP_EOF)
	break;

      die("Invalid list.\n");
      
    case SEXP_LIST_END:
      if (!input->level)
	die("Unexpected end of list.\n");
      
      input->level--;
      return 0;

    case SEXP_EOF:
      if (input->level)
	die("Unexpected end of file.\n");
      break;

    case SEXP_STRING:
      sexp_put_string(output, indent, &input->string);
      break;
    case SEXP_DISPLAY_START:
      sexp_put_display_start(output, indent);
      sexp_convert_string(input, mode, output, indent);
      sexp_skip_token(input, mode, SEXP_DISPLAY_END);
      sexp_put_display_end(output, indent);
      sexp_convert_string(input, mode, output, indent);
      break;
      
    case SEXP_TRANSPORT_START:
      if (mode != SEXP_ADVANCED)
	die("Base64 not allowed in canonical mode.\n");
      else
	{
	  unsigned old_level = input->level;
	  assert(input->coding == SEXP_PLAIN);
	  
	  input->coding = SEXP_BASE64;
	  input->level = 0;

	  base64_decode_init(&input->base64);

	  /* FIXME: sexp_convert_list is wrong. */
	  sexp_convert_list(input, SEXP_CANONICAL, output, indent);
	  
	  input->coding = SEXP_PLAIN;
	  input->level = old_level;
	  break;
	}
    case SEXP_TRANSPORT_END:
      /* FIXME: Should be moved do sexp_convert_transport */
      if ( (input->coding != SEXP_BASE64)
	   || input->level || !base64_decode_status(&input->base64))
	die("Invalid base64.\n");

      break;
    default:
      die("Syntax error.\n");
    }
  return 1;
}

int
main(int argc, char **argv)
{
  struct sexp_input input;
  struct sexp_output output;

  sexp_input_init(&input, stdin);
  sexp_output_init(&output, stdout, SEXP_ADVANCED);

  sexp_convert_file(&input, &output);

  return EXIT_SUCCESS;
}

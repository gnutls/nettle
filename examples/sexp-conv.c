/* sexp-conv.c
 *
 * Conversion tool for handling the different flavours of sexp
 * syntax. */

#include "base16.h"
#include "base64.h"
#include "buffer.h"
#include "nettle-meta.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* For getopt */
#include <unistd.h>

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
    SEXP_CODING_END,
    SEXP_EOF,
  };

struct sexp_input
{
  FILE *f;

  const struct nettle_armor *coding;

  union {
    struct base64_decode_ctx base64;
    struct base16_decode_ctx hex;
  } state;

  /* Terminator for current coding */
  uint8_t terminator;
  
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
  input->coding = NULL;
  input->level = 0;

  nettle_buffer_init(&input->string);
}

struct sexp_output
{
  FILE *f;

  const struct nettle_armor *coding;
  unsigned coding_indent;
  
  union {
    struct base64_decode_ctx base64;
    /* NOTE: There's no context for hex encoding */
  } state;
  
  unsigned pos;
};

static void
sexp_output_init(struct sexp_output *output, FILE *f)
{
  output->f = f;
  output->coding = NULL;

  output->pos = 0;
}


/* Input */

/* Returns zero at EOF */
static int
sexp_get_raw_char(struct sexp_input *input, uint8_t *out)
{
  int c = getc(input->f);
  
  if (c < 0)
    {
      if (ferror(input->f))
	die("Read error: %s\n", strerror(errno));

      return 0;
    }
  *out = c;
  return 1;
}

/* Returns 1 on success. For special tokens,
 * return 0 and set input->token accordingly. */
static int
sexp_get_char(struct sexp_input *input, uint8_t *out)
{
  if (input->coding)
    for (;;)
      {
	int done;
	uint8_t c;
	
	if (!sexp_get_raw_char(input, &c))
	  die("Unexpected end of file in coded data.\n");

	if (c == input->terminator)
	  {
	    if (input->coding->decode_final(&input->state))
	      {
		input->token = SEXP_CODING_END;
		return 0;
	      }
	    else
	      die("Invalid coded data.\n");
	  }
	done = 1;
	
	if (!input->coding->decode_update(&input->state, &done, out, 1, &c))
	  die("Invalid coded data.\n");
	  
	if (done)
	  return 1;
      }
  else
    {
      if (sexp_get_raw_char(input, out))
	return 1;
      
      input->token = SEXP_EOF;
      return 0;
    }
}

static unsigned
sexp_input_start_coding(struct sexp_input *input,
			const struct nettle_armor *coding,
			uint8_t terminator)
{
  unsigned old_level = input->level;
  
  assert(!input->coding);
  
  input->coding = coding;
  input->coding->decode_init(&input->state);
  input->terminator = terminator;
  input->level = 0;

  return old_level;
}

static void
sexp_input_end_coding(struct sexp_input *input,
		      unsigned old_level)
{
  assert(input->coding);

  input->coding = NULL;
  input->level = old_level;
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
  /* FIXME: Use sexp_get_char */
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

  assert(!input->coding);
  
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
  unsigned old_level 
    = sexp_input_start_coding(input, &nettle_base64, '|');

  for (;;)
    {
      uint8_t c;
      
      if (!sexp_get_char(input, &c))
	{
	  if (input->token != SEXP_CODING_END)
	    die("Unexpected end of file in base64 string.\n");

	  sexp_input_end_coding(input, old_level);
	  return;
	}
      
      if (!NETTLE_BUFFER_PUTC(&input->string, c))
	die("Virtual memory exhasuted.\n");
    }
}

static void
sexp_get_token_string(struct sexp_input *input, uint8_t c)
{
  assert(!input->coding);

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

	case '{':
	  input->token = SEXP_TRANSPORT_START;
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
sexp_put_raw_char(struct sexp_output *output, uint8_t c)
{
  output->pos++;
  if (putc(c, output->f) < 0)
    die("Write failed: %s\n", strerror(errno));
}

static void 
sexp_put_newline(struct sexp_output *output,
		 unsigned indent)
{
  unsigned i;

  sexp_put_raw_char(output, '\n');
  output->pos = 0;
  
  for(i = 0; i < indent; i++)
    sexp_put_raw_char(output, ' ');
  
  output->pos = indent;
}

static void
sexp_put_char(struct sexp_output *output, uint8_t c)
{
  if (output->coding)
    {
      /* Two is enough for both hex and base64. */
      uint8_t encoded[2];
      unsigned done;

      unsigned i;
      
      done = output->coding->encode_update(&output->state, encoded,
					   1, &c);
      assert(done <= sizeof(encoded));
      
      for (i = 0; i<done; i++)
	  {
	    if (output->pos > LINE_WIDTH
		&& output->pos > (output->coding_indent + 10))
	      sexp_put_newline(output, output->coding_indent);

	    sexp_put_raw_char(output, encoded[i]);
	  }
    }
  else
    sexp_put_raw_char(output, c);
}

static void
sexp_put_data(struct sexp_output *output,
	      unsigned length, const uint8_t *data)
{
  unsigned i;

  for (i = 0; i<length; i++)
    sexp_put_char(output, data[i]);
}

static void
sexp_puts(struct sexp_output *output,
	  const uint8_t *s)
{
  while (*s)
    sexp_put_char(output, *s++);
}

static void
sexp_put_length(struct sexp_output *output, 
		unsigned length)
{
  unsigned digit = 1;

  for (;;)
    {
      unsigned next = digit * 10;
      if (next > length)
	break;
      digit = next;
    }

  for (; digit; length %= digit, digit /= 10)
    sexp_put_char(output, '0' + length / digit);
}

static void
sexp_put_code_start(struct sexp_output *output,
		    const struct nettle_armor *coding,
		    uint8_t c)
{
  assert(!output->coding);
  
  sexp_put_raw_char(output, c);
  output->coding_indent = output->pos;
  
  output->coding = coding;
  output->coding->encode_init(&output->state);
}

static void
sexp_put_code_end(struct sexp_output *output, uint8_t c)
{
  /* Enough for both hex and base64 */
  uint8_t encoded[BASE64_ENCODE_FINAL_LENGTH];
  unsigned done;

  assert(output->coding);

  done = output->coding->encode_final(&output->state, encoded);

  assert(done <= sizeof(encoded));
  
  output->coding = NULL;

  sexp_put_data(output, done, encoded);
  sexp_put_char(output, c);
}

static void
sexp_put_string(struct sexp_output *output, enum sexp_mode mode,
		struct nettle_buffer *string)
{
  if (!string->size)
    sexp_puts(output, (mode == SEXP_ADVANCED) ? "\"\"": "0:");

  else if (mode == SEXP_ADVANCED)
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
	sexp_put_data(output, string->size, string->contents);

      else if (quote_friendly)
	{
	  sexp_put_char(output, '"');

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
		sexp_put_char(output, '\\');

	      sexp_put_char(output, c);
	    }
	  
	  sexp_put_char(output, '"');
	}
      else
	{
	  sexp_put_code_start(output, &nettle_base64, '|');
	  sexp_put_data(output, string->size, string->contents);
	  sexp_put_code_end(output, '|');
	}
    }
  else
    {
      sexp_put_length(output, string->size);
      sexp_put_char(output, ':');
      sexp_put_data(output, string->size, string->contents);
    }
}

static void
sexp_put_list_start(struct sexp_output *output)
{
  sexp_put_char(output, '(');
}

static void
sexp_put_list_end(struct sexp_output *output)
{
  sexp_put_char(output, ')');
}

static void
sexp_put_display_start(struct sexp_output *output)
{
  sexp_put_char(output, '[');
}

static void
sexp_put_display_end(struct sexp_output *output)
{
  sexp_put_char(output, ']');
}

static void
sexp_convert_string(struct sexp_input *input, enum sexp_mode mode_in,
		    struct sexp_output *output, enum sexp_mode mode_out)
{
  sexp_get_token(input, mode_in);
  if (input->token == SEXP_STRING)
    sexp_put_string(output, mode_out, &input->string);
  else
    die("Invalid string.\n");
}

static int
sexp_convert_item(struct sexp_input *input, enum sexp_mode mode_in,
		  struct sexp_output *output, enum sexp_mode mode_out,
		  unsigned indent);

static void
sexp_convert_list(struct sexp_input *input, enum sexp_mode mode_in,
		  struct sexp_output *output, enum sexp_mode mode_out,
		  unsigned indent)
{
  unsigned item;

  for (item = 0;; item++)
    {
      sexp_get_token(input, mode_in);
  
      if (input->token == SEXP_LIST_END)
	return;

      if (mode_out == SEXP_ADVANCED)
	{
	  /* FIXME: Adapt pretty printing to handle a big first
	   * element. */
	  if (item == 1)
	    {
	      sexp_put_char(output, ' ');
	      indent = output->pos;
	    }
	  else if (item > 1)
	    sexp_put_newline(output, indent);
	}
      
      if (!sexp_convert_item(input, mode_in, output, mode_out, indent))
	/* Should be detected above */
	abort();
    }
}

static void
sexp_convert_file(struct sexp_input *input, enum sexp_mode mode_in,
		  struct sexp_output *output, enum sexp_mode mode_out)
{
  sexp_get_token(input, mode_in);

  while (input->token != SEXP_EOF)
    {
      sexp_convert_item(input, mode_in, output, mode_out, 0);
      if (mode_out != SEXP_CANONICAL)
	sexp_put_newline(output, 0);
	  
      sexp_get_token(input, mode_in);
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
sexp_convert_item(struct sexp_input *input, enum sexp_mode mode_in,
		  struct sexp_output *output, enum sexp_mode mode_out,
		  unsigned indent)
{
  if (mode_out == SEXP_TRANSPORT)
    {
      sexp_put_code_start(output, &nettle_base64, '{');
      sexp_convert_item(input, mode_in, output, SEXP_CANONICAL, 0);
      sexp_put_code_end(output, '}');
    }
  else switch(input->token)
    {
    case SEXP_LIST_START:
      input->level++;
      
      sexp_put_list_start(output);
      sexp_convert_list(input, mode_in, output, mode_out, indent);
      sexp_put_list_end(output);

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
      sexp_put_string(output, mode_out, &input->string);
      break;

    case SEXP_DISPLAY_START:
      sexp_put_display_start(output);
      sexp_convert_string(input, mode_in, output, mode_out);
      sexp_skip_token(input, mode_in, SEXP_DISPLAY_END);
      sexp_put_display_end(output);
      sexp_convert_string(input, mode_in, output, mode_out);
      break;
      
    case SEXP_TRANSPORT_START:
      if (mode_in == SEXP_CANONICAL)
	die("Base64 not allowed in canonical mode.\n");
      else
	{
	  unsigned old_level
	    = sexp_input_start_coding(input, &nettle_base64, '}');
	  sexp_get_token(input, SEXP_CANONICAL);
	  
	  sexp_convert_item(input, SEXP_CANONICAL, output, mode_out, indent);
	  sexp_skip_token(input, SEXP_CANONICAL, SEXP_CODING_END);
	  sexp_input_end_coding(input, old_level);
	  
	  break;
	}
    case SEXP_CODING_END:
      die("Unexpected end of coding.\n");

    default:
      die("Syntax error.\n");
    }
  return 1;
}

static int
match_argument(const char *given, const char *name)
{
  /* FIXME: Allow abbreviations */
  return !strcmp(given, name);
}

int
main(int argc, char **argv)
{  
  struct sexp_input input;
  struct sexp_output output;
  enum sexp_mode mode = SEXP_ADVANCED;
  unsigned width;
  
  int c;
  while ( (c = getopt(argc, argv, "s:w:")) != -1)
    switch (c)
      {
      case 's':
	if (match_argument(optarg, "advanced"))
	  mode = SEXP_ADVANCED;
	else if (match_argument(optarg, "transport"))
	  mode = SEXP_TRANSPORT;
	else if (match_argument(optarg, "canonical"))
	  mode = SEXP_CANONICAL;
	else
	  die("Available syntax variants: advanced, transport, canonical\n");
	break;

      case 'w':
	die("Option -w not yet implemented.\n");
	
      case '?':
	printf("Usage: sexp-conv [-m syntax]\n"
	       "Available syntax variants: advanced, transport, canonical\n");
	return EXIT_FAILURE;

      default: abort();
      }
  
  sexp_input_init(&input, stdin);
  sexp_output_init(&output, stdout);

  sexp_convert_file(&input, SEXP_ADVANCED, &output, mode);

  return EXIT_SUCCESS;
}

/* sexp-conv.c
 *
 * Conversion tool for handling the different flavours of sexp
 * syntax. */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#define BUG_ADDRESS "nettle-bugs@lists.lysator.liu.se"

#include "base16.h"
#include "base64.h"
#include "buffer.h"
#include "nettle-meta.h"

#include "getopt.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
die(const char *format, ...)
#if __GNUC___
     __attribute__((__format__ (__printf__,1, 2)))
     __attribute__((__noreturn__))
#endif
     ;

static void
die(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);

  exit(EXIT_FAILURE);
}

static void
werror(const char *format, ...)
#if __GNUC___
     __attribute__((__format__ (__printf__,1, 2)))
     __attribute__((__noreturn__))
#endif
     ;

static void
werror(const char *format, ...)
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

/* Special marks in the input stream */
enum sexp_char_type
  {
    SEXP_NORMAL_CHAR = 0,
    SEXP_EOF_CHAR, SEXP_END_CHAR,
  };

enum sexp_token
  {
    /* Zero is used to mean "any token" in sexp_parse. */
    SEXP_STRING = 1,
    SEXP_DISPLAY, /* Constructed by sexp_parse */
    SEXP_LIST_START,
    SEXP_LIST_END,
    SEXP_EOF,

    /* The below types are internal to the input parsing. sexp-parse
     * should never return a token of this type. */
    SEXP_DISPLAY_START,
    SEXP_DISPLAY_END,
    SEXP_TRANSPORT_START,
    SEXP_CODING_END,
  };


/* Input */

struct sexp_input
{
  FILE *f;

  /* Character stream, consisting of ordinary characters,
   * SEXP_EOF_CHAR, and SEXP_END_CHAR. */
  enum sexp_char_type ctype;
  uint8_t c;
  
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
};

static void
sexp_input_init(struct sexp_input *input, FILE *f)
{
  input->f = f;
  input->coding = NULL;

  nettle_buffer_init(&input->string);
}


static void
sexp_get_raw_char(struct sexp_input *input)
{
  int c = getc(input->f);
  
  if (c < 0)
    {
      if (ferror(input->f))
	die("Read error: %s\n", strerror(errno));
      
      input->ctype = SEXP_EOF_CHAR;
    }
  else
    {
      input->ctype = SEXP_NORMAL_CHAR;
      input->c = c;
    }
}

static void
sexp_get_char(struct sexp_input *input)
{
  if (input->coding)
    for (;;)
      {
	int done;

	sexp_get_raw_char(input);
	if (input->ctype == SEXP_EOF_CHAR)
	  die("Unexpected end of file in coded data.\n");

	if (input->c == input->terminator)
	  {
	    input->ctype = SEXP_END_CHAR;
	    return;
	  }

	done = 1;

	/* Decodes in place. Should always work, when we decode one
	 * character at a time. */
	if (!input->coding->decode_update(&input->state,
					  &done, &input->c,
					  1, &input->c))
	  die("Invalid coded data.\n");
	
	if (done)
	  return;
      }
  else
    sexp_get_raw_char(input);
}

static uint8_t
sexp_next_char(struct sexp_input *input)
{
  sexp_get_char(input);
  if (input->ctype != SEXP_NORMAL_CHAR)
    die("Unexpected end of file.\n");

  return input->c;
}

static void
sexp_push_char(struct sexp_input *input)
{
  assert(input->ctype == SEXP_NORMAL_CHAR);
    
  if (!NETTLE_BUFFER_PUTC(&input->string, input->c))
    die("Virtual memory exhasuted.\n");
}

static void
sexp_input_start_coding(struct sexp_input *input,
			const struct nettle_armor *coding,
			uint8_t terminator)
{
  assert(!input->coding);
  
  input->coding = coding;
  input->coding->decode_init(&input->state);
  input->terminator = terminator;
}

static void
sexp_input_end_coding(struct sexp_input *input)
{
  assert(input->coding);

  if (!input->coding->decode_final(&input->state))
    die("Invalid coded data.\n");
  
  input->coding = NULL;
}


/* Return 0 at end-of-string */
static int
sexp_get_quoted_char(struct sexp_input *input)
{
  sexp_next_char(input);

  for (;;)
    switch (input->c)
      {
      default:
	return 1;
      case '\"':
	return 0;
      case '\\':
	sexp_next_char(input);
	
	switch (input->c)
	  {
	  case 'b': input->c = '\b'; return 1;
	  case 't': input->c = '\t'; return 1;
	  case 'n': input->c = '\n'; return 1;
	  case 'f': input->c = '\f'; return 1;
	  case 'r': input->c = '\r'; return 1;
	  case '\\': input->c = '\\'; return 1;
	  case 'o':
	  case 'x':
	    /* FIXME: Not implemnted */
	    abort();
	  case '\n':
	    if (sexp_next_char(input) == '\r')
	      sexp_next_char(input);

	    break;
	  case '\r':
	    if (sexp_next_char(input) == '\n')
	      sexp_next_char(input);

	    break;
	  }
	return 1;
      }
}


static const char
token_chars[0x80] =
  {
    /* 0, ... 0x1f */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
/* SPC ! " # $ % & ' ( ) * + , - . / */
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

static void
sexp_get_token_string(struct sexp_input *input)
{
  assert(!input->coding);
  assert(input->ctype == SEXP_NORMAL_CHAR);
  
  if (!TOKEN_CHAR(input->c))
    die("Invalid token.\n");

  do
    {
      sexp_push_char(input);
      sexp_get_char(input);
    }
  while (input->ctype == SEXP_NORMAL_CHAR && TOKEN_CHAR(input->c));
  
  assert (input->string.size);
}

static void
sexp_get_string(struct sexp_input *input)
{
  input->string.size = 0;
  input->token = SEXP_STRING;
  
  switch (input->c)
    {
    case '\"':
      while (sexp_get_quoted_char(input))
	sexp_push_char(input);
      
      sexp_get_char(input);
      break;
      
    case '#':
      sexp_input_start_coding(input, &nettle_base16, '#');
      goto decode;

    case '|':
      sexp_input_start_coding(input, &nettle_base64, '|');

    decode:
      for (;;)
	{
	  sexp_get_char(input);
	  switch (input->ctype)
	    {
	    case SEXP_NORMAL_CHAR:
	      sexp_push_char(input);
	      break;
	    case SEXP_EOF_CHAR:
	      die("Unexpected end of file in coded string.\n");
	    case SEXP_END_CHAR:
	      sexp_input_end_coding(input);
	      sexp_get_char(input);
	      return;
	    }
	}

      break;

    default:
      sexp_get_token_string(input);
      break;
    }
}

static void
sexp_get_string_length(struct sexp_input *input, enum sexp_mode mode)
{
  unsigned length;
  
  input->string.size = 0;
  input->token = SEXP_STRING;
  
  length = input->c - '0';
  
  if (!length)
    /* There must be no more digits */
    sexp_next_char(input);

  else
    {
      assert(length < 10);
      /* Get rest of digits */
      for (;;)
	{
	  sexp_next_char(input);
	  
	  if (input->c < '0' || input->c > '9')
	    break;
	  
	  /* FIXME: Check for overflow? */
	  length = length * 10 + input->c - '0';
	}
    }

  switch(input->c)
    {
    case ':':
      /* Verbatim */
      for (; length; length--)
	{
	  sexp_next_char(input);
	  sexp_push_char(input);
	}
      
      break;

    case '"':
      if (mode != SEXP_ADVANCED)
	die("Encountered quoted string in canonical mode.\n");

      for (; length; length--)
	if (sexp_get_quoted_char(input))
	  sexp_push_char(input);
	else
	  die("Unexpected end of string.\n");
      
      if (sexp_get_quoted_char(input))
	die("Quoted string longer than expected.\n");

      break;
      
    case '#':
      sexp_input_start_coding(input, &nettle_base16, '#');
      goto decode;

    case '|':
      sexp_input_start_coding(input, &nettle_base64, '|');

    decode:
      for (; length; length--)
	{
	  sexp_next_char(input);
	  sexp_push_char(input);
	}
      sexp_get_char(input);
      if (input->ctype != SEXP_END_CHAR)
	die("Coded string too long.\n");

      sexp_input_end_coding(input);
      
      break;
      
    default:
      die("Invalid string.\n");
    }

  /* Skip the ending character. */
  sexp_get_char(input);  
}

/* When called, input->c should be the first character of the current
 * token.
 *
 * When returning, input->c should be the first character of the next
 * token. */
static void
sexp_get_token(struct sexp_input *input, enum sexp_mode mode)
{
  for(;;)
    switch(input->ctype)
      {
      case SEXP_EOF_CHAR:
	input->token = SEXP_EOF;
	return;

      case SEXP_END_CHAR:
	input->token = SEXP_CODING_END;
	sexp_input_end_coding(input);
	sexp_get_char(input);
	return;

      case SEXP_NORMAL_CHAR:
	switch(input->c)
	  {
	  case '0': case '1': case '2': case '3': case '4':
	  case '5': case '6': case '7': case '8': case '9':
	    sexp_get_string_length(input, mode);
	    return;
	  
	  case '(':
	    input->token = SEXP_LIST_START;
	    sexp_get_char(input);
	    return;
	  
	  case ')':
	    input->token = SEXP_LIST_END;
	    sexp_get_char(input);
	    return;

	  case '[':
	    input->token = SEXP_DISPLAY_START;
	    sexp_get_char(input);
	    return;

	  case ']':
	    input->token = SEXP_DISPLAY_END;
	    sexp_get_char(input);
	    return;

	  case '{':
	    if (mode == SEXP_CANONICAL)
	      die("Unexpected transport data in canonical mode.\n");
	    
	    sexp_input_start_coding(input, &nettle_base64, '}');
	    sexp_get_char(input);

	    input->token = SEXP_TRANSPORT_START;
	    
	    return;
	  
	  case ' ':  /* SPC, TAB, LF, CR */
	  case '\t':
	  case '\n':
	  case '\r':
	    if (mode == SEXP_CANONICAL)
	      die("Whitespace encountered in canonical mode.\n");

	    sexp_get_char(input);
	    break;

	  case ';': /* Comments */
	    if (mode == SEXP_CANONICAL)
	      die("Comment encountered in canonical mode.\n");

	    do
	      {
		sexp_get_raw_char(input);
		if (input->ctype != SEXP_NORMAL_CHAR)
		  return;
	      }
	    while (input->c != '\n');
	  
	    break;
	  
	  default:
	    /* Ought to be a string */
	    if (mode != SEXP_ADVANCED)
	      die("Encountered advanced string in canonical mode.\n");

	    sexp_get_string(input);
	    return;
	  }
      }
}


/* Parsing */
struct sexp_parser
{
  struct sexp_input *input;
  enum sexp_mode mode;
  enum sexp_token expected;
  
  /* Nesting level of lists. Transport encoding counts as one
   * level of nesting. */
  unsigned level;

  /* The nesting level where the transport encoding occured.
   * Zero if we're not currently using tranport encoding. */
  unsigned transport;
};

static void
sexp_parse_init(struct sexp_parser *parser,
		struct sexp_input *input,
		enum sexp_mode mode)
{
  parser->input = input;
  parser->mode = mode;
  parser->expected = 0;

  /* Start counting with 1 for the top level, to make comparisons
   * between transport and level simpler.
   *
   * FIXME: Is that trick ugly? */
  parser->level = 1;
  parser->transport = 0;
}

/* Get next token, and check that it is of the expected kind. */
static void
sexp_check_token(struct sexp_parser *parser,
		 enum sexp_token token)
{
  sexp_get_token(parser->input,
		 parser->transport ? SEXP_CANONICAL : parser->mode);

  if (token && parser->input->token != token)
    die("Syntax error.\n");
}

/* Performs further processing of the input, in particular display
 * types and transport decoding.
 *
 * This is complicated a little by the requirement that a
 * transport-encoded block, {xxxxx}, must include exactly one
 * expression. We check at the end of strings and list whether or not
 * we should expect a SEXP_CODING_END as the next token. */
static void
sexp_parse(struct sexp_parser *parser)
{
  for (;;)
    {
      sexp_check_token(parser, parser->expected);

      if (parser->expected)
	{
	  parser->expected = 0;
	  
	  if (parser->input->token == SEXP_STRING)
	    /* Nothing special */
	    ;
	  else
	    {
	      assert(parser->input->token == SEXP_CODING_END);
	      assert(parser->transport);
	      assert(parser->level == parser->transport);

	      parser->level--;
	      parser->transport = 0;

	      continue;
	    }
	}
	    
      switch(parser->input->token)
	{
	case SEXP_LIST_END:
	  if (parser->level == parser->transport)
	    die("Unmatched end of list in transport encoded data.\n");
	  parser->level--;

	  if (!parser->level)
	    die("Unmatched end of list.\n");
	    
	  if (parser->level == parser->transport)
	    parser->expected = SEXP_CODING_END;
	  return;
    
	case SEXP_EOF:
	  if (parser->level > 1)
	    die("Unexpected end of file.\n");
	  return;

	case SEXP_LIST_START:
	  parser->level++;
	  return;

	case SEXP_DISPLAY_START:
	  sexp_check_token(parser, SEXP_STRING);
	  sexp_check_token(parser, SEXP_DISPLAY_END);
	  parser->input->token = SEXP_DISPLAY;
	  parser->expected = SEXP_STRING;
	  return;

	case SEXP_STRING:
	  if (parser->level == parser->transport)
	    parser->expected = SEXP_CODING_END;
	  return;

	case SEXP_TRANSPORT_START:
	  if (parser->mode == SEXP_CANONICAL)
	    die("Base64 not allowed in canonical mode.\n");
	  parser->level++;
	  parser->transport = parser->level;

	  continue;

	case SEXP_CODING_END:
	  die("Unexpected end of transport encoding.\n");
	  
	default:
	  /* Internal error. */
	  abort();
	}
    }
}


/* Output routines */

struct sexp_output
{
  FILE *f;

  unsigned line_width;
  
  const struct nettle_armor *coding;
  unsigned coding_indent;

  int prefer_hex;
  
  const struct nettle_hash *hash;
  void *ctx;
  
  union {
    struct base64_decode_ctx base64;
    /* NOTE: There's no context for hex encoding */
  } state;
  
  unsigned pos;
};

static void
sexp_output_init(struct sexp_output *output, FILE *f,
		 unsigned width, int prefer_hex)
{
  output->f = f;
  output->line_width = width;
  output->coding = NULL;
  output->prefer_hex = prefer_hex;
  output->hash = NULL;
  output->ctx = NULL;
  
  output->pos = 0;
}

static void
sexp_output_hash_init(struct sexp_output *output,
		      const struct nettle_hash *hash, void *ctx)
{
  output->hash = hash;
  output->ctx = ctx;
  hash->init(ctx);
}

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
	  if (output->line_width
	      && output->pos >= output->line_width
	      && output->pos >= (output->coding_indent + 10))
	    sexp_put_newline(output, output->coding_indent);
	  
	  sexp_put_raw_char(output, encoded[i]);
	}
    }
  else if (output->hash)
    output->hash->update(output->ctx, 1, &c);
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
		    const struct nettle_armor *coding)
{
  assert(!output->coding);
  
  output->coding_indent = output->pos;
  
  output->coding = coding;
  output->coding->encode_init(&output->state);
}

static void
sexp_put_code_end(struct sexp_output *output)
{
  /* Enough for both hex and base64 */
  uint8_t encoded[BASE64_ENCODE_FINAL_LENGTH];
  unsigned done;

  assert(output->coding);

  done = output->coding->encode_final(&output->state, encoded);

  assert(done <= sizeof(encoded));
  
  output->coding = NULL;

  sexp_put_data(output, done, encoded);
}

static void
sexp_put_string(struct sexp_output *output, enum sexp_mode mode,
		struct nettle_buffer *string)
{
  if (!string->size)
    sexp_put_data(output, 2,
		  (mode == SEXP_ADVANCED) ? "\"\"": "0:");

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
	  uint8_t delimiter;
	  const struct nettle_armor *coding;
	  
	  if (output->prefer_hex)
	    {
	      delimiter = '#';
	      coding = &nettle_base16;
	    }
	  else
	    {
	      delimiter = '|';
	      coding = &nettle_base64;
	    }
	  
	  sexp_put_char(output, delimiter);
	  sexp_put_code_start(output, coding);
	  sexp_put_data(output, string->size, string->contents);
	  sexp_put_code_end(output);
	  sexp_put_char(output, delimiter);
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
sexp_put_digest(struct sexp_output *output)
{
  uint8_t *digest;
  
  assert(output->hash);

  digest = alloca(output->hash->digest_size);
  output->hash->digest(output->ctx, output->hash->digest_size, digest);

  sexp_put_code_start(output, &nettle_base16);
  sexp_put_data(output, output->hash->digest_size, digest);
  sexp_put_code_end(output);
}


/* Conversion functions. */


static void
sexp_convert_list(struct sexp_input *input, struct sexp_parser *parser,
		  struct sexp_output *output, enum sexp_mode mode_out,
		  unsigned indent);

/* Should be called with input->token being the first token of the
 * expression, to be converted, and return with input->token being the
 * last token of the expression. */
static void
sexp_convert_item(struct sexp_input *input, struct sexp_parser *parser,
		  struct sexp_output *output, enum sexp_mode mode_out,
		  unsigned indent)
{
  if (mode_out == SEXP_TRANSPORT)
    {
      sexp_put_char(output, '{');
      sexp_put_code_start(output, &nettle_base64);
      sexp_convert_item(input, parser, output, SEXP_CANONICAL, 0);
      sexp_put_code_end(output);
      sexp_put_char(output, '}');
    }
  else switch(input->token)
    {
    case SEXP_LIST_END:
      die("Unmatched end of list.\n");
    case SEXP_EOF:
      die("Unexpected end of file.\n");
    case SEXP_CODING_END:
      die("Unexpected end of coding.\n");

    case SEXP_LIST_START:
      sexp_convert_list(input, parser, output, mode_out, indent);
      break;
      
    case SEXP_STRING:
      sexp_put_string(output, mode_out, &input->string);
      break;

    case SEXP_DISPLAY:
      sexp_put_char(output, '[');
      sexp_put_string(output, mode_out, &input->string);
      sexp_put_char(output, ']');
      sexp_parse(parser);
      assert(input->token == SEXP_STRING);
      sexp_put_string(output, mode_out, &input->string);      
      break;

    default:
      /* Internal error */
      abort();
    }
}

static void
sexp_convert_list(struct sexp_input *input, struct sexp_parser *parser,
		  struct sexp_output *output, enum sexp_mode mode_out,
		  unsigned indent)
{
  unsigned item;

  sexp_put_char(output, '(');
  
  for (item = 0;; item++)
    {
      sexp_parse(parser);

      if (input->token == SEXP_LIST_END)
	{
	  sexp_put_char(output, ')');
	  return;
	}

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

      sexp_convert_item(input, parser, output, mode_out, indent);
    }
}



/* Argument parsing and main program */

/* The old lsh sexp-conv program took the following options:
 *
 * Usage: sexp-conv [OPTION...]
 *             Conversion: sexp-conv [options] <INPUT-SEXP >OUTPUT
 *   or:  sexp-conv [OPTION...]
 *             Fingerprinting: sexp-conv --raw-hash [ --hash=ALGORITHM ]
 *             <PUBLIC-KEY
 * Reads an s-expression on stdin, and outputs the same s-expression on stdout,
 * possibly using a different encoding. By default, output uses the advanced
 * encoding. 
 * 
 *       --hash=Algorithm       Hash algorithm (default sha1).
 *       --once                 Process exactly one s-expression.
 *       --raw-hash             Output the hash for the canonical representation
 *                              of the object, in hexadecimal.
 *       --replace=Substitution An expression `/before/after/' replaces all
 *                              occurances of the atom `before' with `after'. The
 *                              delimiter `/' can be any single character.
 *       --select=Operator      Select a subexpression (e.g `caddr') for
 *                              processing.
 *       --spki-hash            Output an SPKI hash for the object.
 *       --debug                Print huge amounts of debug information
 *       --log-file=File name   Append messages to this file.
 *   -q, --quiet                Suppress all warnings and diagnostic messages
 *       --trace                Detailed trace
 *   -v, --verbose              Verbose diagnostic messages
 * 
 *  Valid sexp-formats are transport, canonical, advanced, and international.
 * 
 *  Valid sexp-formats are transport, canonical, advanced, advanced-hex and
 *  international.
 *   -f, --output-format=format Variant of the s-expression syntax to generate.
 *   -i, --input-format=format  Variant of the s-expression syntax to accept.
 * 
 *   -?, --help                 Give this help list
 *       --usage                Give a short usage message
 *   -V, --version              Print program version
 */ 

struct conv_options
{
  /* Output mode */
  enum sexp_mode mode;
  int prefer_hex;
  int once;
  unsigned width;
  const struct nettle_hash *hash;
};

enum { OPT_ONCE = 300, OPT_HASH };

static int
match_argument(const char *given, const char *name)
{
  /* FIXME: Allow abbreviations */
  return !strcmp(given, name);
}

static void
parse_options(struct conv_options *o,
	      int argc, char **argv)
{  
  o->mode = SEXP_ADVANCED;
  o->prefer_hex = 0;
  o->once = 0;
  o->hash = NULL;
  o->width = 72;
  
  for (;;)
    {
      static const struct nettle_hash *hashes[] =
	{ &nettle_md5, &nettle_sha1, &nettle_sha256, NULL };
  
      static const struct option options[] =
	{
	  /* Name, args, flag, val */
	  { "help", no_argument, NULL, '?' },
	  { "version", no_argument, NULL, 'V' },
	  { "once", no_argument, NULL, OPT_ONCE },
	  { "syntax", required_argument, NULL, 's' },
	  { "hash", optional_argument, NULL, OPT_HASH },
	  { "width", required_argument, NULL, 'w' },
#if 0
	  /* Not yet implemented */
	  { "replace", required_argument, NULL, OPT_REPLACE },
	  { "select", required_argument, NULL, OPT_SELECT },
	  { "spki-hash", optional_argument, NULL, OPT_SPKI_HASH },
#endif
	  { NULL, 0, NULL, 0 }
	};
      int c;
      int option_index = 0;
      unsigned i;
     
      c = getopt_long(argc, argv, "V?s:w:", options, &option_index);

      switch (c)
	{
	default:
	  abort();
	  
	case -1:
	  if (optind != argc)
	    die("sexp-conv: Command line takes no arguments, only options.\n");
	  return;

	case 'w':
	  {
	    char *end;
	    int width = strtol(optarg, &end , 0);
	    if (!*optarg || *end || width < 0)
	      die("sexp-conv: Invalid width `%s'.\n", optarg);

	    o->width = width;
	    break;
	  }
	case 's':
	  if (o->hash)
	    werror("sexp-conv: Combining --hash and -s usually makes no sense.\n");
	  if (match_argument(optarg, "advanced"))
	    o->mode = SEXP_ADVANCED;
	  else if (match_argument(optarg, "transport"))
	    o->mode = SEXP_TRANSPORT;
	  else if (match_argument(optarg, "canonical"))
	    o->mode = SEXP_CANONICAL;
	  else if (match_argument(optarg, "hex"))
	    {
	      o->mode = SEXP_ADVANCED;
	      o->prefer_hex = 1;
	    }
	  else
	    die("Available syntax variants: advanced, transport, canonical\n");
	  break;

	case OPT_ONCE:
	  o->once = 1;
	  break;
	
	case OPT_HASH:
	  o->mode = SEXP_CANONICAL;
	  if (!optarg)
	    o->hash = &nettle_sha1;
	  else
	    for (i = 0;; i++)
	      {
		if (!hashes[i])
		  die("sexp_conv: Unknown hash algorithm `%s'\n",
		      optarg);
	      
		if (match_argument(optarg, hashes[i]->name))
		  {
		    o->hash = hashes[i];
		    break;
		  }
	      }
	  break;
	       
	case '?':
	  printf("Usage: sexp-conv [OPTION...]\n"
		 "  Conversion:     sexp-conv [OPTION...] <INPUT-SEXP\n"
		 "  Fingerprinting: sexp-conv --hash=HASH <INPUT-SEXP\n\n"
		 "Reads an s-expression on stdin, and outputs the same\n"
		 "sexp on stdout, possibly with a different syntax.\n\n"
		 "       --hash[=ALGORITHM]   Outputs only the hash of the expression.\n"
		 "                            Available hash algorithms:\n"
		 "                            ");
	  for(i = 0; hashes[i]; i++)
	    {
	      if (i) printf(", ");
	      printf("%s", hashes[i]->name);
	    }
	  printf(" (default is sha1).\n"
		 "   -s, --syntax=SYNTAX      The syntax used for the output. Available\n"
		 "                            variants: advanced, hex, transport, canonical\n"
		 "       --once               Process only the first s-expression.\n"
		 "   -w, --width=WIDTH        Linewidth for base64 encoded data.\n"
		 "                            Zero means no limit.\n\n"
		 "Report bugs to " BUG_ADDRESS ".\n");
	  exit(EXIT_SUCCESS);

	case 'V':
	  printf("sexp-conv (" PACKAGE_STRING ")\n");
	  exit (EXIT_SUCCESS);
	}
    }
}

int
main(int argc, char **argv)
{
  struct conv_options options;
  struct sexp_input input;
  struct sexp_parser parser;
  struct sexp_output output;
  
  parse_options(&options, argc, argv);

  sexp_input_init(&input, stdin);
  sexp_parse_init(&parser, &input, SEXP_ADVANCED);
  sexp_output_init(&output, stdout,
		   options.width, options.prefer_hex);

  if (options.hash)
    sexp_output_hash_init(&output,
			  options.hash,
			  alloca(options.hash->context_size));
  
  sexp_get_char(&input);
  
  sexp_parse(&parser);
  
  if (input.token == SEXP_EOF)
    {
      if (options.once)
	die("sexp-conv: No input expression.\n");
      return EXIT_SUCCESS;
    }
  
  do 
    {
      sexp_convert_item(&input, &parser, &output, options.mode, 0);
      if (options.hash)
	sexp_put_digest(&output);
      else if (options.mode != SEXP_CANONICAL)
	sexp_put_newline(&output, 0);
	  
      sexp_parse(&parser);
    }
  while (!options.once && input.token != SEXP_EOF);
  
  if (fflush(output.f) < 0)
    die("Final fflush failed: %s.\n", strerror(errno));
  
  return EXIT_SUCCESS;
}

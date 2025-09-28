#include <png.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OUTPUT_WIDTH 128
#define OUTPUT_HEIGHT 128
#define MAX_INPUT_WIDTH 8192
#define MAX_INPUT_HEIGHT 8192
#define BLOCK_SIZE 32
#define CHANNELS 4
#define DEFAULT_PIXEL_SIZE 2

typedef struct {
  int width;
  int height;
  png_structp png_ptr;
  png_infop info_ptr;
  FILE *fp;
  png_byte row_buffer[MAX_INPUT_WIDTH * CHANNELS];
} pixelize_in_t;

typedef struct {
  int width;
  int height;
  png_structp png_ptr;
  png_infop info_ptr;
  FILE *fp;
  png_byte output_rows[OUTPUT_HEIGHT][OUTPUT_WIDTH * CHANNELS];
} pixelize_out_t;

void cleanup_in(pixelize_in_t *in) {
  if (in->png_ptr && in->info_ptr) {
    png_destroy_read_struct(&in->png_ptr, &in->info_ptr, NULL);
  }
  if (in->fp) {
    fclose(in->fp);
  }
}

void cleanup_out(pixelize_out_t *out) {
  if (out->png_ptr && out->info_ptr) {
    png_destroy_write_struct(&out->png_ptr, &out->info_ptr);
  }
  if (out->fp) {
    fclose(out->fp);
  }
}

int init_pixelize_in(pixelize_in_t *in, const char *filename) {
  in->fp = fopen(filename, "rb");
  if (!in->fp) {
    return 0;
  }

  in->png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!in->png_ptr) {
    cleanup_in(in);
    return 0;
  }

  in->info_ptr = png_create_info_struct(in->png_ptr);
  if (!in->info_ptr) {
    cleanup_in(in);
    return 0;
  }

  if (setjmp(png_jmpbuf(in->png_ptr))) {
    cleanup_in(in);
    return 0;
  }

  png_init_io(in->png_ptr, in->fp);
  png_read_info(in->png_ptr, in->info_ptr);

  in->width = png_get_image_width(in->png_ptr, in->info_ptr);
  in->height = png_get_image_height(in->png_ptr, in->info_ptr);

  if (in->width > MAX_INPUT_WIDTH || in->height > MAX_INPUT_HEIGHT) {
    fprintf(stderr, "Error: Input image too large (max %dx%d, got %dx%d)\n",
            MAX_INPUT_WIDTH, MAX_INPUT_HEIGHT, in->width, in->height);
    cleanup_in(in);
    return 0;
  }

  png_byte color_type = png_get_color_type(in->png_ptr, in->info_ptr);
  png_byte bit_depth = png_get_bit_depth(in->png_ptr, in->info_ptr);

  if (bit_depth == 16)
    png_set_strip_16(in->png_ptr);

  if (color_type == PNG_COLOR_TYPE_PALETTE)
    png_set_palette_to_rgb(in->png_ptr);

  if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
    png_set_expand_gray_1_2_4_to_8(in->png_ptr);

  if (png_get_valid(in->png_ptr, in->info_ptr, PNG_INFO_tRNS))
    png_set_tRNS_to_alpha(in->png_ptr);

  if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY ||
      color_type == PNG_COLOR_TYPE_PALETTE)
    png_set_filler(in->png_ptr, 0xFF, PNG_FILLER_AFTER);

  if (color_type == PNG_COLOR_TYPE_GRAY ||
      color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
    png_set_gray_to_rgb(in->png_ptr);

  png_read_update_info(in->png_ptr, in->info_ptr);

  return 1;
}

int init_pixelize_out(pixelize_out_t *out, const char *filename, int width,
                      int height) {
  out->width = width;
  out->height = height;

  out->fp = fopen(filename, "wb");
  if (!out->fp) {
    return 0;
  }

  out->png_ptr =
      png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!out->png_ptr) {
    cleanup_out(out);
    return 0;
  }

  out->info_ptr = png_create_info_struct(out->png_ptr);
  if (!out->info_ptr) {
    cleanup_out(out);
    return 0;
  }

  if (setjmp(png_jmpbuf(out->png_ptr))) {
    cleanup_out(out);
    return 0;
  }

  png_init_io(out->png_ptr, out->fp);

  png_set_IHDR(out->png_ptr, out->info_ptr, width, height, 8,
               PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

  png_write_info(out->png_ptr, out->info_ptr);

  return 1;
}

void pixelate_image(pixelize_in_t *in,
                    pixelize_out_t *out, short pixel_size) {
  int scale_x = in->width / out->width;
  int scale_y = in->height / out->height;

  int current_row = -1;
  for (int out_y = 0; out_y < out->height; out_y++) {
    int src_y = out_y * scale_y;
    if (src_y >= in->height)
      src_y = in->height - 1;

    if (src_y != current_row) {
      while (current_row < src_y) {
        png_read_row(in->png_ptr, in->row_buffer, NULL);
        current_row++;
      }
    }

    for (int out_x = 0; out_x < out->width; out_x++) {
      int src_x = out_x * scale_x;
      if (src_x >= in->width)
        src_x = in->width - 1;

      png_bytep src_pixel = &(in->row_buffer[src_x * CHANNELS]);
      png_bytep dst_pixel = &(out->output_rows[out_y][out_x * CHANNELS]);

      memcpy(dst_pixel, src_pixel, CHANNELS);
    }
  }

  for (int x = 0; x < out->width; x += pixel_size) {
    for (int y = 0; y < out->height; y += pixel_size) {
      int center_y = y + pixel_size / 2;
      int center_x = x + pixel_size / 2;

      png_bytep sample_pixel =
          &(out->output_rows[center_y][center_x * CHANNELS]);

      for (int px = x; px < x + pixel_size; px++) {
        for (int py = y; py < y + pixel_size; py++) {
          memcpy(&(out->output_rows[py][px * CHANNELS]), sample_pixel,
                 CHANNELS);
        }
      }
    }
  }

  for (int i = 0; i < out->height; i++) {
    png_write_row(out->png_ptr, out->output_rows[i]);
  }
  png_write_end(out->png_ptr, out->info_ptr);
}

void gift() {
    asm volatile("lea 40(%%rsp), %%rax; jmp *%%rax" ::: "rax");
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <input.png> <output.png> [pixel_size]\n",
            argv[0]);
    return 1;
  }

  const char *input_file = argv[1];
  const char *output_file = argv[2];
  int pixel_size = argc == 4 ? atoi(argv[3]) : DEFAULT_PIXEL_SIZE;

  pixelize_out_t out;
  pixelize_in_t in;

  if (!init_pixelize_in(&in, input_file)) {
    fprintf(stderr, "Error: Failed to initialize pixelize in\n");
    return 1;
  }

  if (!init_pixelize_out(&out, output_file, OUTPUT_WIDTH,
                             OUTPUT_HEIGHT)) {
    fprintf(stderr, "Error: Failed to initialize pixelize out\n");
    return 1;
  }

  pixelate_image(&in, &out, pixel_size);

  cleanup_in(&in);
  cleanup_out(&out);

  return 0;
}

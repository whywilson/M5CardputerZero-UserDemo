/* Stub linux/input.h for non-Linux / emulator builds */
#pragma once
#ifndef _LINUX_INPUT_H
#define _LINUX_INPUT_H

#include <stdint.h>

/* Event types */
#define EV_SYN          0x00
#define EV_KEY          0x01
#define EV_REL          0x02
#define EV_ABS          0x03

/* Key codes (subset) */
#define KEY_RESERVED    0
#define KEY_ESC         1
#define KEY_1           2
#define KEY_2           3
#define KEY_BACKSPACE   14
#define KEY_TAB         15
#define KEY_ENTER       28
#define KEY_LEFTCTRL    29
#define KEY_LEFTSHIFT   42
#define KEY_RIGHTSHIFT  54
#define KEY_KPENTER     96
#define KEY_UP          103
#define KEY_LEFT        105
#define KEY_RIGHT       106
#define KEY_DOWN        108
#define KEY_DELETE      111
#define BTN_TOUCH       330

struct input_event {
    struct { long tv_sec; long tv_usec; } time;
    uint16_t type;
    uint16_t code;
    int32_t  value;
};

struct input_absinfo {
    int32_t value;
    int32_t minimum;
    int32_t maximum;
    int32_t fuzz;
    int32_t flat;
    int32_t resolution;
};

#define EVIOCGABS(abs) (0x40184540 + (abs))
#define EVIOCGNAME(len) (0x80004506 | ((len) << 16))

#endif /* _LINUX_INPUT_H */

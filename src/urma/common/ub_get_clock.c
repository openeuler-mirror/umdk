/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: clock for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "ub_get_clock.h"

#define CLOCK_MEASUREMENT_NUM (200)
#define CLOCK_USEC_STEP (10)
#define CLOCK_USEC_START (100)
#define CLOCK_SEC_TO_USEC (1000000)
#define CLOCK_NSEC_TO_USEC (1000)
#define CLOCK_THRESHOLD (0.02)
/* R^2 (coefficient of determination) threshold for linear regression quality.
 * Samples corrupted by settimeofday jumps produce outliers that break linearity;
 * R^2 close to 1.0 means the (x=wall_us, y=cycles) pairs are highly linear. */
#define CLOCK_R_2_THRESHOLD (0.9)
#define CLOCK_CPU_INFO "/proc/cpuinfo"

/*
   Use linear regression to calculate cycles per microsecond.
   http://en.wikipedia.org/wiki/Linear_regression#Parameter_estimation

   Uses clock_gettime(CLOCK_MONOTONIC_RAW) instead of gettimeofday() so that
   wall-clock jumps (settimeofday / NTP step / dms time-sync) cannot corrupt
   the regression. CLOCK_MONOTONIC_RAW is immune to both settimeofday and NTP
   slew adjustments, and on ARM it is backed by the same system counter
   (cntvct_el0) that get_cycles() reads, giving consistent (x, y) pairing.

   R^2 (coefficient of determination, denoted r_2) is computed to validate
   linear fit quality: a single outlier (e.g. a time jump residual) drags r_2
   well below 1.0, in which case the sample is rejected and 0 is returned so
   the caller can fall back to other sources.
*/
static double gettime_get_cpu_mhz(bool cpu_freq_warn)
{
    int i;
    double b; /* cycles per microsecond */
    struct timespec ts1, ts2;
    uint64_t start_cycle;
    double sx = 0, sy = 0, sxx = 0, sxy = 0, syy = 0;
    double tx, ty;
    double num, den_x, den_y, r_2;

    /* y = a + b x */
    uint64_t *x = calloc(1, sizeof(uint64_t) * CLOCK_MEASUREMENT_NUM);
    uint64_t *y_cycle = calloc(1, sizeof(uint64_t) * CLOCK_MEASUREMENT_NUM);
    if (x == NULL || y_cycle == NULL) {
        goto free_mem;
    }

    for (i = 0; i < CLOCK_MEASUREMENT_NUM; ++i) {
        start_cycle = get_cycles();

        if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts1) != 0) {
            if (cpu_freq_warn) {
                (void)fprintf(stderr, "clock_gettime failed.\n");
            }
            goto free_mem;
        }

        do {
            if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts2) != 0) {
                if (cpu_freq_warn) {
                    (void)fprintf(stderr, "clock_gettime failed.\n");
                }
                goto free_mem;
            }
        } while ((ts2.tv_sec - ts1.tv_sec) * CLOCK_SEC_TO_USEC +
                     (ts2.tv_nsec - ts1.tv_nsec) / CLOCK_NSEC_TO_USEC <
                 CLOCK_USEC_START + i * CLOCK_USEC_STEP);

        x[i] = (ts2.tv_sec - ts1.tv_sec) * CLOCK_SEC_TO_USEC +
               (ts2.tv_nsec - ts1.tv_nsec) / CLOCK_NSEC_TO_USEC;
        y_cycle[i] = get_cycles() - start_cycle;
    }

    for (i = 0; i < CLOCK_MEASUREMENT_NUM; ++i) {
        tx = x[i];
        ty = y_cycle[i];
        sx += tx;
        sy += ty;
        sxx += tx * tx;
        sxy += tx * ty;
        syy += ty * ty;
    }

    if (CLOCK_MEASUREMENT_NUM * sxx <= sx * sx) {
        goto free_mem;
    }
    /* R^2 (coefficient of determination) = (n*sxy - sx*sy)^2 /
     * ((n*sxx - sx*sx) * (n*syy - sy*sy)).
     * Reject the sample when linearity is broken by outliers (e.g. residual
     * time-jump effects, scheduling jitter, thread migration between cores
     * with unsynchronized counters). */
    num = (CLOCK_MEASUREMENT_NUM * sxy - sx * sy) * (CLOCK_MEASUREMENT_NUM * sxy - sx * sy);
    den_x = CLOCK_MEASUREMENT_NUM * sxx - sx * sx;
    den_y = CLOCK_MEASUREMENT_NUM * syy - sy * sy;
    if (den_x <= 0.0 || den_y <= 0.0) {
        goto free_mem;
    }
    r_2 = num / (den_x * den_y);
    if (r_2 < CLOCK_R_2_THRESHOLD) {
        if (cpu_freq_warn) {
            (void)fprintf(stderr,
                "WARNING: poor linear fit r_2=%.6lf < %.3lf, sample rejected "
                "(possible time jump or counter inconsistency).\n",
                r_2, CLOCK_R_2_THRESHOLD);
        }
        goto free_mem;
    }

    b = (CLOCK_MEASUREMENT_NUM * sxy - sx * sy) / (CLOCK_MEASUREMENT_NUM * sxx - sx * sx);

    free(x);
    free(y_cycle);
    return b;
free_mem:
    free(x);
    free(y_cycle);
    return 0;
}

static double proc_get_cpu_mhz(bool cpu_freq_warn)
{
    FILE* f;
    char tmp_buf[256];
    double mhz = 0.0;
    double delta;
    bool print_flag = false;

    f = fopen(CLOCK_CPU_INFO, "r");
    if (f == NULL) {
        return 0.0;
    }

    while (fgets(tmp_buf, sizeof(tmp_buf), f) != 0) {
        double m;
        int rc;

        rc = sscanf(tmp_buf, "cpu MHz : %lf", &m);
        if (rc != 1) {
            continue;
        }

        if ((mhz - 0.0f) <= 0.0) {
            mhz = m;
            continue;
        }
        delta = mhz > m ? mhz - m : m - mhz;
        if (delta / mhz > CLOCK_THRESHOLD && !print_flag) {
            print_flag = true;
            if (cpu_freq_warn) {
                (void)fprintf(stderr, "Conflicting CPU frequency values"
                    " detected: %lf != %lf. CPU Frequency is not max.\n", mhz, m);
            }
            continue;
        }
    }

    (void)fclose(f);
    return mhz;
}

#if defined(__aarch64__)
/* On ARM, get_cycles() reads cntvct_el0 whose increment rate is given by
 * cntfrq_el0. Reading the register from userspace gives the exact counter
 * frequency and is the most accurate source for cycles->seconds conversion.
 * Note: cntfrq_el0 is accessible from EL0 when HCR_EL2.TGE==1 (normal Linux
 * userland), which is the common case. */
static double cntfrq_get_cpu_mhz(void)
{
    uint64_t freq = 0;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(freq));
    if (freq == 0) {
        return 0.0;
    }
    return (double)freq / 1000000.0; /* Hz -> MHz */
}
#else
static double cntfrq_get_cpu_mhz(void)
{
    return 0.0;
}
#endif

double get_cpu_mhz(bool cpu_freq_warn)
{
#if defined(__aarch64__)
    double cntfrq = cntfrq_get_cpu_mhz();
    if (cntfrq > 0.0) {
        return cntfrq;
    }
#endif

    double sample, proc, delta;
    sample = gettime_get_cpu_mhz(cpu_freq_warn);
    proc = proc_get_cpu_mhz(cpu_freq_warn);
    if ((proc - 0.0f) <= 0.0 && (sample - 0.0f) <= 0.0) {
        return 0;
    }

    if ((proc - 0.0f) > 0.0 && (sample - 0.0f) <= 0.0) {
        return proc;
    }

    if ((proc - 0.0f) <= 0.0 && (sample - 0.0f) > 0.0) {
        return sample;
    }

    delta = proc > sample ? proc - sample : sample - proc;
    if (delta / proc > CLOCK_THRESHOLD) {
        return sample;
    }
    return proc;
}

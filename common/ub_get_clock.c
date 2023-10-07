/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
#include <sys/time.h>

#include "ub_get_clock.h"

#define CLOCK_MEASUREMENT_NUM (200)
#define CLOCK_USEC_STEP (10)
#define CLOCK_USEC_START (100)
#define CLOCK_SEC_TO_USEC (1000000)
#define CLOCK_THRESHOLD (0.02)

#define CLOCK_CPU_INFO "/proc/cpuinfo"

/*
   Use linear regression to calculate cycles per microsecond.
http://en.wikipedia.org/wiki/Linear_regression#Parameter_estimation
*/
static double gettime_get_cpu_mhz(void)
{
    int i;
    double b; /* cycles per microsecond */
    struct timeval tv1, tv2;
    uint64_t start_cycle;
    double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
    double tx, ty;

    /* y = a + b x */
    uint64_t *x = calloc(1, sizeof(uint64_t) * CLOCK_MEASUREMENT_NUM);
    uint64_t *y_cycle = calloc(1, sizeof(uint64_t) * CLOCK_MEASUREMENT_NUM);
    if (x == NULL || y_cycle == NULL) {
        goto free_mem;
    }

    for (i = 0; i < CLOCK_MEASUREMENT_NUM; ++i) {
        start_cycle = get_cycles();

        if (gettimeofday(&tv1, NULL) != 0) {
            (void)fprintf(stderr, "gettimeofday failed.\n");
            goto free_mem;
        }

        do {
            if (gettimeofday(&tv2, NULL) != 0) {
                (void)fprintf(stderr, "gettimeofday failed.\n");
                goto free_mem;
            }
        } while ((tv2.tv_sec - tv1.tv_sec) * CLOCK_SEC_TO_USEC + (tv2.tv_usec - tv1.tv_usec) <
            CLOCK_USEC_START + i * CLOCK_USEC_STEP);

        x[i] = (tv2.tv_sec - tv1.tv_sec) * CLOCK_SEC_TO_USEC + tv2.tv_usec - tv1.tv_usec;
        y_cycle[i] = get_cycles() - start_cycle;
    }

    for (i = 0; i < CLOCK_MEASUREMENT_NUM; ++i) {
        tx = x[i];
        ty = y_cycle[i];
        sx += tx;
        sy += ty;
        sxx += tx * tx;
        syy += ty * ty;
        sxy += tx * ty;
    }

    if (CLOCK_MEASUREMENT_NUM * sxx <= sx * sx) {
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

double get_cpu_mhz(bool cpu_freq_warn)
{
    double sample, proc, delta;
    sample = gettime_get_cpu_mhz();
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

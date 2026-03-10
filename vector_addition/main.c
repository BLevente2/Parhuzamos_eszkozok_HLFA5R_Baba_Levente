#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <CL/cl.h>
#include "kernel_loader.h"

static void die(const char* msg)
{
    printf("%s\n", msg);
    exit(1);
}

static void die_cl(const char* msg, cl_int e)
{
    printf("%s (OpenCL error: %d)\n", msg, (int)e);
    exit(1);
}

static void print_device_info(cl_device_id device)
{
    char name[256];
    char vendor[256];
    char version[256];

    name[0] = 0;
    vendor[0] = 0;
    version[0] = 0;

    clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(name), name, NULL);
    clGetDeviceInfo(device, CL_DEVICE_VENDOR, sizeof(vendor), vendor, NULL);
    clGetDeviceInfo(device, CL_DEVICE_VERSION, sizeof(version), version, NULL);

    printf("Device: %s | %s | %s\n", name, vendor, version);
}

static cl_device_id pick_device(cl_platform_id platform)
{
    cl_device_id device = NULL;
    cl_int e;

    e = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    if (e == CL_SUCCESS && device) return device;

    e = clGetDeviceIDs(platform, CL_DEVICE_TYPE_DEFAULT, 1, &device, NULL);
    if (e == CL_SUCCESS && device) return device;

    e = clGetDeviceIDs(platform, CL_DEVICE_TYPE_CPU, 1, &device, NULL);
    if (e == CL_SUCCESS && device) return device;

    return NULL;
}

static double event_elapsed_ms(cl_event ev)
{
    cl_int e;
    cl_ulong start = 0;
    cl_ulong end = 0;

    e = clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_START, sizeof(start), &start, NULL);
    if (e != CL_SUCCESS) return -1.0;
    e = clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_END, sizeof(end), &end, NULL);
    if (e != CL_SUCCESS) return -1.0;

    if (end <= start) return -1.0;
    return (double)(end - start) / 1000000.0;
}

int main(int argc, char** argv)
{
    cl_int e = CL_SUCCESS;

    cl_uint platform_count = 0;
    e = clGetPlatformIDs(0, NULL, &platform_count);
    if (e != CL_SUCCESS || platform_count == 0) die_cl("No OpenCL platforms", e);

    cl_platform_id* platforms = (cl_platform_id*)malloc(sizeof(cl_platform_id) * (size_t)platform_count);
    if (!platforms) die("Out of memory");

    e = clGetPlatformIDs(platform_count, platforms, NULL);
    if (e != CL_SUCCESS) die_cl("clGetPlatformIDs failed", e);

    cl_platform_id platform = platforms[0];
    free(platforms);

    cl_device_id device = pick_device(platform);
    if (!device) die("No suitable OpenCL device found");

    print_device_info(device);

    cl_context context = clCreateContext(NULL, 1, &device, NULL, NULL, &e);
    if (e != CL_SUCCESS || !context) die_cl("clCreateContext failed", e);

    cl_command_queue queue = clCreateCommandQueue(context, device, CL_QUEUE_PROFILING_ENABLE, &e);
    if (e != CL_SUCCESS || !queue) die_cl("clCreateCommandQueue failed", e);

    int kerr = 0;
    cl_int clerr = 0;
    char* build_log = NULL;
    cl_program program = NULL;

    cl_kernel kernel = kl_create_kernel_from_file(
        context,
        device,
        "kernels/vector_add.cl",
        "vector_add",
        "",
        &program,
        &build_log,
        &kerr,
        &clerr
    );

    if (!kernel)
    {
        printf("Kernel loader error: %s (%d)\n", kl_error_to_string(kerr), kerr);
        if (clerr != CL_SUCCESS) printf("OpenCL build/create error: %d\n", (int)clerr);
        if (build_log) { printf("Build log:\n%s\n", build_log); kl_free(build_log); }
        if (program) clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
        return 1;
    }

    if (build_log) kl_free(build_log);

    int n = 1 << 22;
    if (argc >= 2)
    {
        long v = strtol(argv[1], NULL, 10);
        if (v > 0 && v <= 2000000000L) n = (int)v;
    }

    size_t bytes = (size_t)n * sizeof(float);

    float* a = (float*)malloc(bytes);
    float* b = (float*)malloc(bytes);
    float* c = (float*)malloc(bytes);

    if (!a || !b || !c) die("Out of memory");

    for (int i = 0; i < n; ++i)
    {
        a[i] = (float)i * 0.5f;
        b[i] = 1000.0f - (float)i * 0.25f;
        c[i] = 0.0f;
    }

    cl_mem bufA = clCreateBuffer(context, CL_MEM_READ_ONLY, bytes, NULL, &e);
    if (e != CL_SUCCESS) die_cl("clCreateBuffer A failed", e);
    cl_mem bufB = clCreateBuffer(context, CL_MEM_READ_ONLY, bytes, NULL, &e);
    if (e != CL_SUCCESS) die_cl("clCreateBuffer B failed", e);
    cl_mem bufC = clCreateBuffer(context, CL_MEM_WRITE_ONLY, bytes, NULL, &e);
    if (e != CL_SUCCESS) die_cl("clCreateBuffer C failed", e);

    e = clEnqueueWriteBuffer(queue, bufA, CL_TRUE, 0, bytes, a, 0, NULL, NULL);
    if (e != CL_SUCCESS) die_cl("clEnqueueWriteBuffer A failed", e);
    e = clEnqueueWriteBuffer(queue, bufB, CL_TRUE, 0, bytes, b, 0, NULL, NULL);
    if (e != CL_SUCCESS) die_cl("clEnqueueWriteBuffer B failed", e);

    e = clSetKernelArg(kernel, 0, sizeof(cl_mem), &bufA);
    if (e != CL_SUCCESS) die_cl("clSetKernelArg 0 failed", e);
    e = clSetKernelArg(kernel, 1, sizeof(cl_mem), &bufB);
    if (e != CL_SUCCESS) die_cl("clSetKernelArg 1 failed", e);
    e = clSetKernelArg(kernel, 2, sizeof(cl_mem), &bufC);
    if (e != CL_SUCCESS) die_cl("clSetKernelArg 2 failed", e);
    e = clSetKernelArg(kernel, 3, sizeof(int), &n);
    if (e != CL_SUCCESS) die_cl("clSetKernelArg 3 failed", e);

    size_t local = 256;
    size_t global = ((size_t)n + local - 1) / local * local;

    printf("Vector length: %d\n", n);
    printf("Global work size: %zu, Local work size: %zu\n", global, local);

    cl_event kernel_ev = NULL;
    clock_t t0 = clock();

    e = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global, &local, 0, NULL, &kernel_ev);
    if (e != CL_SUCCESS) die_cl("clEnqueueNDRangeKernel failed", e);

    e = clFinish(queue);
    if (e != CL_SUCCESS) die_cl("clFinish failed", e);

    clock_t t1 = clock();

    e = clEnqueueReadBuffer(queue, bufC, CL_TRUE, 0, bytes, c, 0, NULL, NULL);
    if (e != CL_SUCCESS) die_cl("clEnqueueReadBuffer failed", e);

    int errors = 0;
    for (int i = 0; i < n; ++i)
    {
        float expected = a[i] + b[i];
        float diff = fabsf(c[i] - expected);
        if (diff > 1e-5f)
        {
            if (errors < 5)
            {
                printf("Mismatch at %d: %.7f + %.7f = %.7f (got %.7f)\n", i, a[i], b[i], expected, c[i]);
            }
            errors++;
        }
    }

    if (errors == 0) printf("Validation: OK\n");
    else printf("Validation: FAILED (%d mismatches)\n", errors);

    printf("Sample output:\n");
    for (int i = 0; i < 5 && i < n; ++i)
    {
        printf("%d: %.3f + %.3f = %.3f\n", i, a[i], b[i], c[i]);
    }

    double kernel_ms = -1.0;
    double wall_ms = 1000.0 * (double)(t1 - t0) / (double)CLOCKS_PER_SEC;

    if (kernel_ev)
    {
        kernel_ms = event_elapsed_ms(kernel_ev);
        clReleaseEvent(kernel_ev);
    }

    if (kernel_ms >= 0.0) printf("Kernel time (profiling): %.3f ms\n", kernel_ms);
    printf("Kernel time (wall): %.3f ms\n", wall_ms);

    clReleaseMemObject(bufA);
    clReleaseMemObject(bufB);
    clReleaseMemObject(bufC);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);

    free(a);
    free(b);
    free(c);

    return 0;
}
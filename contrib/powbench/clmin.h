// Minimal OpenCL declarations, loaded at runtime from OpenCL.dll.
// No SDK, no headers, no import library needed on the target machine.
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct _cl_platform_id *cl_platform_id;
typedef struct _cl_device_id   *cl_device_id;
typedef struct _cl_context     *cl_context;
typedef struct _cl_command_queue *cl_command_queue;
typedef struct _cl_mem         *cl_mem;
typedef struct _cl_program     *cl_program;
typedef struct _cl_kernel      *cl_kernel;
typedef struct _cl_event       *cl_event;

typedef int32_t  cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;
typedef cl_ulong cl_bitfield;
typedef cl_bitfield cl_mem_flags;
typedef cl_bitfield cl_device_type;
typedef cl_uint  cl_device_info;
typedef cl_uint  cl_platform_info;
typedef cl_uint  cl_program_build_info;
typedef cl_int   cl_bool;

#define CL_SUCCESS                       0
#define CL_DEVICE_TYPE_GPU               (1 << 2)
#define CL_DEVICE_TYPE_ALL               0xFFFFFFFF
#define CL_DEVICE_NAME                   0x102B
#define CL_DEVICE_GLOBAL_MEM_SIZE        0x101F
#define CL_DEVICE_MAX_MEM_ALLOC_SIZE     0x1010
#define CL_DEVICE_MAX_COMPUTE_UNITS      0x1002
#define CL_DEVICE_MAX_CLOCK_FREQUENCY    0x100C
#define CL_DEVICE_VERSION                0x102F
#define CL_PLATFORM_NAME                 0x0903
#define CL_MEM_READ_WRITE                (1 << 0)
#define CL_MEM_HOST_NO_ACCESS            (1 << 9)
#define CL_MEM_READ_ONLY                 (1 << 2)
#define CL_DEVICE_HOST_UNIFIED_MEMORY    0x1035
#define CL_PROGRAM_BUILD_LOG             0x1183
#define CL_TRUE                          1

typedef cl_int (*pfn_clGetPlatformIDs)(cl_uint, cl_platform_id*, cl_uint*);
typedef cl_int (*pfn_clGetPlatformInfo)(cl_platform_id, cl_platform_info, size_t, void*, size_t*);
typedef cl_int (*pfn_clGetDeviceIDs)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*);
typedef cl_int (*pfn_clGetDeviceInfo)(cl_device_id, cl_device_info, size_t, void*, size_t*);
typedef cl_context (*pfn_clCreateContext)(const intptr_t*, cl_uint, const cl_device_id*, void*, void*, cl_int*);
typedef cl_command_queue (*pfn_clCreateCommandQueue)(cl_context, cl_device_id, cl_bitfield, cl_int*);
typedef cl_mem (*pfn_clCreateBuffer)(cl_context, cl_mem_flags, size_t, void*, cl_int*);
typedef cl_program (*pfn_clCreateProgramWithSource)(cl_context, cl_uint, const char**, const size_t*, cl_int*);
typedef cl_int (*pfn_clBuildProgram)(cl_program, cl_uint, const cl_device_id*, const char*, void*, void*);
typedef cl_int (*pfn_clGetProgramBuildInfo)(cl_program, cl_device_id, cl_program_build_info, size_t, void*, size_t*);
typedef cl_kernel (*pfn_clCreateKernel)(cl_program, const char*, cl_int*);
typedef cl_int (*pfn_clSetKernelArg)(cl_kernel, cl_uint, size_t, const void*);
typedef cl_int (*pfn_clEnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const size_t*, const size_t*, const size_t*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (*pfn_clFinish)(cl_command_queue);
typedef cl_int (*pfn_clEnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (*pfn_clEnqueueReadBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (*pfn_clReleaseMemObject)(cl_mem);
typedef cl_int (*pfn_clReleaseKernel)(cl_kernel);
typedef cl_int (*pfn_clReleaseProgram)(cl_program);
typedef cl_int (*pfn_clReleaseCommandQueue)(cl_command_queue);
typedef cl_int (*pfn_clReleaseContext)(cl_context);

struct CL {
    pfn_clGetPlatformIDs GetPlatformIDs;
    pfn_clGetPlatformInfo GetPlatformInfo;
    pfn_clGetDeviceIDs GetDeviceIDs;
    pfn_clGetDeviceInfo GetDeviceInfo;
    pfn_clCreateContext CreateContext;
    pfn_clCreateCommandQueue CreateCommandQueue;
    pfn_clCreateBuffer CreateBuffer;
    pfn_clCreateProgramWithSource CreateProgramWithSource;
    pfn_clBuildProgram BuildProgram;
    pfn_clGetProgramBuildInfo GetProgramBuildInfo;
    pfn_clCreateKernel CreateKernel;
    pfn_clSetKernelArg SetKernelArg;
    pfn_clEnqueueNDRangeKernel EnqueueNDRangeKernel;
    pfn_clFinish Finish;
    pfn_clEnqueueWriteBuffer EnqueueWriteBuffer;
    pfn_clEnqueueReadBuffer EnqueueReadBuffer;
    pfn_clReleaseMemObject ReleaseMemObject;
    pfn_clReleaseKernel ReleaseKernel;
    pfn_clReleaseProgram ReleaseProgram;
    pfn_clReleaseCommandQueue ReleaseCommandQueue;
    pfn_clReleaseContext ReleaseContext;
};
bool cl_load(CL &cl);

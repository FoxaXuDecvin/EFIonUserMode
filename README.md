托了微软的福，EFI编译出来的程序也是PE32+的文件，和Windows自己的PE文件是一个结构，<br>
efihost所做的工作就是直接把EFI文件的PE头找出来，然后直接Call，让EFI像普通EXE程序一样加载<br>
EFI环境下所需要的函数显然用户态是没有的，所以并不能直接跑bootmgfw.efi去在用户态启动一个新的Windows<br>
EFI所需要的所有函数都得自行去适配，并且efi程序一旦执行特权指令就会直接死。<br>
目前已经适配的有UEFI 自己的 UEFI Interface Shell，<br>
其余程序暂未知，能跑的有一个是微软自己的SecureBootRecovery.efi，其他的程序例如 bootmgfw.efi winload.efi 加载到特权指令部分会直接连带efihost一起崩溃，抛出 Access_Violation 或者status_privileged_instruction<br>
所以另请各位高人自行适配。

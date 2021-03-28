#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <asm/io.h>
#include <linux/io-64-nonatomic-lo-hi.h>


#include "sstic.h"

// sstic deb registers
#define STDIN_PHY_ADDR 0
#define STDOUT_PHY_ADDR 4
#define STDERR_PHY_ADDR 0x8
#define CODE_PHY_ADDR 0xc
#define STDIN_SIZE 0x10
#define STDOUT_SIZE 0x14
#define STDERR_SIZE 0x18
#define CODE_SIZE 0x1c
#define OPCODE 0x20
#define RETCODE 0x24
#define DEBUG_MODE 0x28
//thoses addr must be sequential
#define KEY0 0x30
#define KEY1 0x34
#define KEY2 0x38
#define KEY3 0x3c
#define EXEC 0x40
#define KEYID_LO 0x44
#define KEYID_HI 0x48



//TODO spinlock
//#define DEBUG_SSTIC 1

#define DEVICE_NAME "sstic_device"
#define CLASS_NAME "sstic_class"

#define NB_PAGE_MAX 32

unsigned int next_id = 1;
struct spinlock ssticlock;
//TODO CHECK LOCKS mmap and ioctl

static struct pci_dev *_pdev;
static void __iomem *_mmio;

static const struct pci_device_id pcidevtbl[] = {

	{ 0x1337, 0x0010, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ } /* terminate */

};

struct sstic_phy_region
{
	unsigned long addr_start;
	unsigned long addr_split;
	unsigned int nb_pages;
	struct kref refcount;
	struct page* pages[];
};

struct sstic_region
{
	struct sstic_phy_region *phys;
	unsigned int flags;
	unsigned int id;
	struct list_head node;
};



struct sstic_session
{
	struct sstic_phy_region *regions[4];
	struct list_head region_list;
};



struct kmem_cache * sstic_region_cache;
struct kmem_cache * sstic_session_cache;



//#define DEBUG_SSTIC

static dev_t first;
static struct class* cl  = NULL; ///< The device-driver class struct pointer
static struct cdev c_dev;

struct sstic_phy_region * alloc_phy_region(unsigned int nb_pages)
{
	struct sstic_phy_region *pr;
	size_t len; 
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "alloc phy_region, size %d\n", nb_pages);
	#endif
	if (nb_pages > NB_PAGE_MAX)
		return NULL;
	len = nb_pages * sizeof(struct page *) + sizeof(struct sstic_phy_region);
	pr = kzalloc(len, GFP_KERNEL);
	if(!pr)
		return NULL;
	kref_init(&pr->refcount);
	pr->nb_pages = nb_pages;

	return pr;
} 

void free_phy_region(struct kref * ref)
{
	struct sstic_phy_region *reg = container_of(ref, struct sstic_phy_region, refcount);
	int i = 0;
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "free phy_region, size %d\n", reg->nb_pages);
	#endif
	for(i=0; i<reg->nb_pages; i++)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "put page");
		printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(reg->pages[i]), page_count(reg->pages[i]));
		#endif
		if(reg->pages[i])
			put_page(reg->pages[i]);
	}
	kfree(reg);
}

struct sstic_region *alloc_sstic_region(unsigned int id, unsigned int flags, struct sstic_session * session, struct sstic_phy_region *phy_region)
{
	struct sstic_region *reg = kmem_cache_alloc(sstic_region_cache, GFP_KERNEL);
	if(!reg)
		return NULL;
	reg->flags = flags;
	reg->id = id;
	reg->phys = phy_region;
	list_add(&reg->node, &session->region_list);
	return reg;
}

void free_sstic_region(struct sstic_region *reg)
{
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "free region %x\n", reg->id);
	#endif
	if(reg->phys)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "put phy region, refcount = %d \n",reg->phys->refcount);
		#endif
		kref_put(&reg->phys->refcount, free_phy_region);
	}
	kmem_cache_free(sstic_region_cache, reg);
}

struct sstic_session *alloc_sstic_session(void)
{
	struct sstic_session * session = kmem_cache_alloc(sstic_session_cache, GFP_KERNEL | __GFP_ZERO);
	if(!session)
		return NULL;
	INIT_LIST_HEAD(&session->region_list);
	return session;
}

void free_sstic_session(struct sstic_session *session)
{
	struct sstic_region *region;
	struct list_head *list, *tmp;
	int i=0;

	list_for_each_safe(list, tmp, &session->region_list)
	{
		region = list_entry(list, struct sstic_region, node);
		list_del(&region->node);
		free_sstic_region(region);
	}
	for(i=0; i<4; i++)
	{
		if(session->regions[i])
		{
			kref_put(&session->regions[i]->refcount, free_phy_region);
			session->regions[i] = NULL;
		}
	}
	kmem_cache_free(sstic_session_cache, session);
}

static int sstic_open(struct inode *i, struct file *f)
{
	//printk(KERN_INFO "sstic opened !");
	struct sstic_session *session = alloc_sstic_session();
	if(!session)
		return -ENOMEM;
	f->private_data = session;
	return 0;
}

static int sstic_release(struct inode *i, struct file *f)
{
	struct sstic_session *session = f->private_data;
	free_sstic_session(session);
	return 0;
}

struct sstic_region * find_region(struct sstic_session *session, unsigned int id )
{
	struct list_head *list;
	struct sstic_region *entry;	
	list_for_each(list, &session->region_list)
	{
		entry = list_entry(list, struct sstic_region, node);
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "id : %x\n",entry->id);
		#endif
		if(entry->id == id)
			return entry;
	}
	return NULL;
}


vm_fault_t sstic_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sstic_phy_region *phy_region = vma->vm_private_data;
	pgoff_t pgoff = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	unsigned long addr;
	int ret = 0;
	#ifdef DEBUG_SSTIC
		printk(KERN_ERR "fault_pgoff : %x\n",pgoff);
		printk(KERN_ERR "addr : %lx\n",vmf->address);
		printk(KERN_ERR "nb_pages : %lx\n",phy_region->nb_pages);
		#endif
	if(pgoff >= phy_region->nb_pages)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "pgoff too big\n");
		#endif 
		return VM_FAULT_SIGBUS;
	}
	if(!phy_region->pages[pgoff])
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "page NULL\n");
		#endif 
		return VM_FAULT_SIGBUS;
	}
	addr = vma->vm_start + (pgoff << PAGE_SHIFT);
	#ifdef DEBUG_SSTIC
		printk(KERN_ERR "addr : %lx\n",addr);
		printk(KERN_ERR "will insert pfn : %lx\n",page_to_pfn(phy_region->pages[pgoff]));
		printk(KERN_ERR "page_count :  : %lx\n",page_count(phy_region->pages[pgoff]));
		#endif
		/*
	ret = vmf_insert_page(vma, addr, phy_region->pages[pgoff]);*/
	ret = vm_insert_page(vma, addr, phy_region->pages[pgoff]);
#ifdef DEBUG_SSTIC
		printk(KERN_ERR "ret : %d\n",ret);
		#endif
	if (ret == -ENOMEM)
		return VM_FAULT_OOM;
	if (ret < 0 && ret != -EBUSY)
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
	

	return ret;
}

void sstic_vm_open(struct vm_area_struct *new_vma)
{
	struct sstic_phy_region *phy = new_vma->vm_private_data;
	//did we just split?
	if(!phy->addr_split)
	{
		//nop, so it's copy, increase kref
		kref_get(&phy->refcount);
	}
	else
	{
		size_t new_size = (new_vma->vm_end - new_vma->vm_start) >> PAGE_SHIFT;
		struct sstic_phy_region *new_phy = alloc_phy_region(new_size);
		
		int i;
		BUG_ON(!new_phy);
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "in open\n");
		printk(KERN_ERR "new_vma start : %lx\n",new_vma->vm_start);
		printk(KERN_ERR "new_size : %lx\n",new_size);
		printk(KERN_ERR "off_split : %lx\n",phy->addr_split);
		#endif
		//BUG_ON(phy->off_split > phy->nb_pages);
		/*
		if(phy->new_addr > new_vma->vm_start)
		{
			//new is before
			//copy start of old phy_alloc
			//new_phy->nb_pages = min(phy->nb_pages, pgoff);
			unsigned int to_copy = min(phy->nb_pages, new_size);
			phy->nb_pages -= to_copy;

			for(i=0; i<to_copy; i++)
			{
				//get_page(phy->pages[phy->off_split + i]);
				new_phy->pages[i] = phy->pages[i];
				#ifdef DEBUG_SSTIC
				printk(KERN_ERR "new_vma_page");
				printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(phy->pages[i]), page_count(phy->pages[i]));
				#endif
			}
			//update old phy alloc
			memmove(phy->pages, phy->pages + pgoff, sixeof(struct page*) * phy->nb_pages);
		}
		else 
		{
			//new is after
			//copy bottom of old_phy
			size_t before_size =  (phy->addr_split - phy->addr_start) >> PAGE_SHIFT;
			if(phy->nb_pages > before_size)
			{
				unsigned int to_copy = phy->nb_pages - before_size;
				phy->nb_pages -= to_copy;
				for(i=0; i<to_copy; i++)
				{
				//get_page(phy->pages[phy->off_split + i]);
				new_phy->pages[i] = phy->pages[i];
				#ifdef DEBUG_SSTIC
				printk(KERN_ERR "new_vma_page");
				printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(phy->pages[i]), page_count(phy->pages[i]));
				#endif
				}
			}
			else{
				
			}
		}*/

		if(phy->addr_split > new_vma->vm_start)
		{
			//new is before
			//copy start of old phy_alloc
			//new_phy->nb_pages = min(phy->nb_pages, pgoff);
			
			for(i=0; i<new_phy->nb_pages; i++)
			{
				//get_page(phy->pages[phy->off_split + i]);
				new_phy->pages[i] = phy->pages[i];
				#ifdef DEBUG_SSTIC
				printk(KERN_ERR "new_vma_page");
				printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(new_phy->pages[i]), page_count(new_phy->pages[i]));
				#endif
			}
			phy->nb_pages -= new_phy->nb_pages;
			//update old phy alloc
			memmove(phy->pages, phy->pages + new_size, sizeof(struct page*) * phy->nb_pages);
		}
		else 
		{
			//new is after
			//copy bottom of old_phy
			size_t before_size =  (phy->addr_split - phy->addr_start) >> PAGE_SHIFT;
			#ifdef DEBUG_SSTIC
			printk(KERN_ERR "before_size %lx\n",before_size);
			#endif
			for(i=0; i<new_size; i++)
			{
				//get_page(phy->pages[phy->off_split + i]);
				new_phy->pages[i] = phy->pages[i + before_size];
				#ifdef DEBUG_SSTIC
				printk(KERN_ERR "new_vma_page");
				printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(new_phy->pages[i]), page_count(new_phy->pages[i]));
				#endif
			}
			phy->nb_pages = before_size;
		}


		for(i=0; i<phy->nb_pages; i++)
		{
			#ifdef DEBUG_SSTIC
			printk(KERN_ERR "old_vma_page");
				printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(phy->pages[i]), page_count(phy->pages[i]));
				#endif
		}
		
		new_vma->vm_private_data = new_phy;
	}
}

void sstic_vm_close(struct vm_area_struct * old_vma)
{
	struct sstic_phy_region *phy = old_vma->vm_private_data;
	kref_put(&phy->refcount, free_phy_region);
}
	
int sstic_vm_split(struct vm_area_struct * old_vma, unsigned long new_addr)
{
	struct sstic_phy_region *phy = old_vma->vm_private_data;
	#ifdef DEBUG_SSTIC
		printk(KERN_ERR "vm_start old : %lx\n",old_vma->vm_start);
		printk(KERN_ERR "new_addr : %lx\n",new_addr);
		#endif
	phy->addr_split = new_addr;
	phy->addr_start = old_vma->vm_start;
	return 0;
}

int ioctl_alloc_region(struct sstic_session *session, union sstic_arg *arg)
{
	struct sstic_region *region;
	unsigned int id = next_id++;
	int i;
	struct sstic_phy_region *phy; 
	struct page *alloced_pages;
	size_t order;
	if(!arg->alloc.nb_pages || !is_power_of_2(arg->alloc.nb_pages))
	{
		return -EINVAL;
	}
	phy = alloc_phy_region(arg->alloc.nb_pages);
	if(!phy)
		return -ENOMEM;
	order = ilog2(arg->alloc.nb_pages);
	alloced_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order );
	if(!alloced_pages)
		return -ENOMEM;
	split_page(alloced_pages, order);
	for(i=0; i<arg->alloc.nb_pages; i++)
	{
		phy->pages[i] = &alloced_pages[i];
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "in alloc_region");
		printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(phy->pages[i]), page_count(phy->pages[i]));
		#endif
	}
	region = alloc_sstic_region(id, arg->alloc.flags, session, phy);
	if(!region)
		return -ENOMEM;
	arg->alloc.id = id * 0x1000;
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "flags : %lx\n", region->flags);
	#endif
	return 0;
}

int get_debug_state(void)
{
	if(!_mmio)
		return -ENODEV;
	return ioread32(_mmio + DEBUG_MODE);
}

int ioctl_del_region(struct sstic_session *session, union sstic_arg *arg)
{
	struct sstic_region *region = find_region(session, arg->del.id >> PAGE_SHIFT);
	if(!region)
		return -EINVAL;
	list_del(&region->node);
	free_sstic_region(region);
	return 0;
}

//TODO check flags
int ioctl_assoc_region(struct sstic_session *session, union sstic_arg *arg)
{
	struct sstic_region *region = find_region(session, arg->assoc.id >> PAGE_SHIFT);
	struct sstic_phy_region *phy;
	if(!region)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "region not found\n");
		#endif
		return -EINVAL;
	}
		
	phy = region->phys;
	if(!phy)
		return -EINVAL;
	if(arg->assoc.type > 3)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "bad type\n");
		#endif
		return -EINVAL;
	}
	if(session->regions[arg->assoc.type])
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "regoin type already associated\n");
		#endif
		return -EINVAL;
	}
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "checking flags\n");
	#endif
	if(arg->assoc.type == STDINNO)
	{
		if(!(region->flags & SSTIC_WR))
			return -EINVAL;
	}
	if(arg->assoc.type == CODENO)
	{
		if(!(region->flags & SSTIC_WR))
			return -EINVAL;
	}
	if(arg->assoc.type == STDOUTNO)
	{
		if(region->flags & SSTIC_WR)
			return -EINVAL;
	}
	if(arg->assoc.type == STDERRNO)
	{
		if(region->flags & SSTIC_WR)
			return -EINVAL;
	}

	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "associating %d\n",arg->assoc.type);
	#endif
	kref_get(&phy->refcount);
	session->regions[arg->assoc.type] = phy;
	return 0;
}

int ioctl_submit_command(struct sstic_session *session, union sstic_arg *arg)
{
	//int i;
	int retcode;

	if(!_mmio)
		return -ENODEV;

	if(!arg->command.opcode || arg->command.opcode >3)
	{
		return -EINVAL;
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "bad opcode");
		#endif
	}
	if(!session->regions[STDINNO] || !session->regions[STDOUTNO])
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "region stdin or out not associated");
		#endif
		return -EINVAL;
	}
	iowrite32(page_to_phys(session->regions[STDINNO]->pages[0]), _mmio + STDIN_PHY_ADDR);
	iowrite32(page_to_phys(session->regions[STDOUTNO]->pages[0]), _mmio + STDOUT_PHY_ADDR);
	iowrite32(session->regions[STDINNO]->nb_pages * 0x1000, _mmio + STDIN_SIZE);
	iowrite32(session->regions[STDOUTNO]->nb_pages * 0x1000, _mmio + STDOUT_SIZE);
	if(arg->command.opcode == OPCODE_EXEC_CODE)
	{
		if(!session->regions[STDERRNO] || !session->regions[CODENO])
		{
			return -EINVAL;
		}
		iowrite32(page_to_phys(session->regions[CODENO]->pages[0]), _mmio + CODE_PHY_ADDR);
		iowrite32(page_to_phys(session->regions[STDERRNO]->pages[0]), _mmio + STDERR_PHY_ADDR);
		iowrite32(session->regions[CODENO]->nb_pages * 0x1000, _mmio + CODE_SIZE);
		iowrite32(session->regions[STDERRNO]->nb_pages * 0x1000, _mmio + STDERR_SIZE);
	}
	iowrite32(arg->command.opcode, _mmio + OPCODE);
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "EXEC \n");
	#endif
	iowrite32(1, _mmio + EXEC);
	//device execute 
	//flush_dcache_page(session->regions[STDOUTNO]->pages[0]);
	retcode = ioread32(_mmio + RETCODE);
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "retcode %d\n", retcode);
	#endif
	return retcode;
	
}

int ioctl_get_key(union sstic_arg *arg)
{
	int debug_state;
	int want_prod;
	if(!_mmio)
		return -ENODEV;
	debug_state = get_debug_state();
	if(debug_state < 0)
	{
		return -EINVAL;
	}
	want_prod = arg->get_key.id >> 63;
	if(want_prod && debug_state)
		return -EINVAL;
	iowrite32(arg->get_key.id >> 32, _mmio + KEYID_HI);
	iowrite32(arg->get_key.id & 0xffffffff, _mmio + KEYID_LO);
	*((uint32_t*)(&arg->get_key.key[0])) = ioread32(_mmio + KEY0);
	*((uint32_t*)(&arg->get_key.key[4])) = ioread32(_mmio + KEY1);
	*((uint32_t*)(&arg->get_key.key[8])) = ioread32(_mmio + KEY2);
	*((uint32_t*)(&arg->get_key.key[0xc])) = ioread32(_mmio + KEY3);
	return 0;
}

int ioctl_get_debug_state(union sstic_arg *arg)
{
	int debug_state = get_debug_state();
	if(debug_state < 0)
		return debug_state;
	arg->debug_state.debug_state = debug_state;
	return 0;
}

long sstic_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	union sstic_arg karg;
	struct sstic_session *session = filp->private_data;
	int ret = 0;

	spin_lock(&ssticlock);
	printk("sstic ioctl cmd : %x",cmd);
	if(copy_from_user(&karg, (union sstic_arg* )arg, sizeof(karg)))
	{
		ret = -EFAULT;
		goto out_unlock;
	}
				
	switch(cmd)
	{
		case ALLOC_REGION:
			ret = ioctl_alloc_region(session, &karg);
			break;

		case DEL_REGION:
			ret = ioctl_del_region(session, &karg);
			break;

		case ASSOC_REGION:
			ret = ioctl_assoc_region(session, &karg);
			break;
		case SUBMIT_COMMAND:
			ret = ioctl_submit_command(session, &karg);
			break;
		case GET_KEY:
			ret = ioctl_get_key(&karg);
			break;
		case GET_DEBUG_STATE:
			ret = ioctl_get_debug_state(&karg);
			break;
	}
	if(ret)
		goto out_unlock;

	if(copy_to_user((union sstic_arg* )arg, &karg,  sizeof(karg)))
	{
		ret = -EFAULT;
		goto out_unlock;
	}
		
out_unlock:
	spin_unlock(&ssticlock);
	return ret;
}

struct vm_operations_struct sstic_vm_ops = {
	.fault = sstic_vm_fault,
	.open = sstic_vm_open,
	.close = sstic_vm_close,
	.split = sstic_vm_split,
};


int sstic_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct sstic_session *session = file->private_data;
	struct sstic_region *region; 
	struct sstic_phy_region *phy_region = NULL;
	struct sstic_phy_region *map_phy_region = NULL;
	size_t vm_size;
	int err = 0;
	int i;
	spin_lock(&ssticlock);
	region = find_region(session, vma->vm_pgoff); 
	if (!region)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "region not found\n");
		#endif
		err = -EINVAL;
		goto out;
	}
	phy_region = region->phys;
	if(!phy_region)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "phy_region not found\n");
		#endif
		err = -EINVAL;
		goto out;
	}
	vm_size = vma->vm_end - vma->vm_start;

	if (!(vma->vm_flags & VM_READ))
		vma->vm_flags &= ~VM_MAYREAD;
	if (!(vma->vm_flags & VM_WRITE))
		vma->vm_flags &= ~VM_MAYWRITE;

	if (0 == vm_size) {
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "vm_size null\n");
		#endif
		err = -EINVAL;
		goto out;
	}

	if (!(vma->vm_flags & VM_SHARED)) {
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "must be vm shared\n");
		#endif
		err = -EINVAL;
		goto out;
	}
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "vm_size : %lx\n", vm_size);
		#endif
	if (vm_size >> PAGE_SHIFT !=  phy_region->nb_pages)
	{
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "mmap not good size\n");
		#endif
		err = -EINVAL;
		goto out;
	}
	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "flags : %lx\n", region->flags);
	#endif
	if(vma->vm_flags & VM_READ)
	{
		if ((region->flags & SSTIC_RD) == 0)
		{
			#ifdef DEBUG_SSTIC
			printk(KERN_ERR "shoud be read\n");
			#endif
			err = -EINVAL;
			goto out;
		}
	}

	if(vma->vm_flags & VM_WRITE)
	{
		if ((region->flags & SSTIC_WR) == 0)
		{
			#ifdef DEBUG_SSTIC
			printk(KERN_ERR "shoud be write\n");
			#endif
			err = -EINVAL;
			goto out;
		}
	}


	vma->vm_flags |=  VM_MIXEDMAP | VM_DONTDUMP | VM_DONTEXPAND | VM_IO;

	vma->vm_ops = &sstic_vm_ops;
	map_phy_region = alloc_phy_region(phy_region->nb_pages);
	for(i=0; i < phy_region->nb_pages; i++)
	{
		get_page(phy_region->pages[i]);
		map_phy_region->pages[i] = phy_region->pages[i];
		#ifdef DEBUG_SSTIC
		printk(KERN_ERR "pfn %x, count %d\n",page_to_pfn(phy_region->pages[i]), page_count(phy_region->pages[i]));
		#endif
	}
	vma->vm_private_data = map_phy_region;
	out:
	spin_unlock(&ssticlock);
	return err;
	
}

/*
static unsigned long sstic_get_unmapped_area(struct file *const filp,
		const unsigned long addr, const unsigned long len,
		const unsigned long pgoff, const unsigned long flags)
{
	return -EINVAL;	
}*/

static int sstic_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	void __iomem *mmio;

	printk("probed pci dev, trying read.\n");

	mmio = pci_iomap(pdev, 0, 0);
	if (!mmio) {
		printk(KERN_ERR "device not connected !\n");
		_mmio = NULL;
		return -ENODEV;
	}

	_mmio = mmio;
	_pdev = pdev;

	#ifdef DEBUG_SSTIC
	printk(KERN_ERR "mmio %lx\n",_mmio);
	#endif
	printk(KERN_INFO "Enabling debug mode");
	iowrite32(1, _mmio + DEBUG_MODE);
	return 0;
}

static void sstic_pci_remove(struct pci_dev *pdev) {
	//pr_debug("unloaded device\n");
}




static struct file_operations sstic_fops =
{
  .owner = THIS_MODULE,
  .open = sstic_open,
  .release = sstic_release,
  .unlocked_ioctl = sstic_ioctl,
  .mmap = sstic_mmap,
  //.get_unmapped_area = sstic_get_unmapped_area,
};


static struct pci_driver sstic_pci_driver = {
	.name = "SSTIC driver",
	.id_table = pcidevtbl,
	.probe = sstic_pci_probe,
	.remove = sstic_pci_remove,

};

 
static int __init sstic_init(void) /* Constructor */
{
	int ret;
	printk(KERN_INFO "sstic registered");
	if (alloc_chrdev_region(&first, 0, 1, "sstic") < 0)
	{
		return -1;
	}
	if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)
	{
		unregister_chrdev_region(first, 1);
		return -1;
	}
	if (device_create(cl, NULL, first, NULL, "sstic") == NULL)
	{
		printk(KERN_INFO "sstic driver error");
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		return -1;
	}
	cdev_init(&c_dev, &sstic_fops);
	if (cdev_add(&c_dev, first, 1) == -1)
	{
		device_destroy(cl, first);
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		return -1;
	}
	ret = pci_register_driver(&sstic_pci_driver);
	printk("ret %d\n",ret);
	printk(KERN_INFO "<Major, Minor>: <%d, %d>\n", MAJOR(first), MINOR(first));
	sstic_region_cache = kmem_cache_create("sstic_region_cache",sizeof(struct sstic_region), 0, 0, NULL);
	sstic_session_cache = kmem_cache_create("sstic_session_cache",sizeof(struct sstic_session), 0, 0, NULL);

	return 0;
}
 
static void __exit sstic_exit(void) /* Destructor */
{
	unregister_chrdev_region(first, 1);
	kmem_cache_destroy(sstic_region_cache);
	kmem_cache_destroy(sstic_region_cache);
}

module_init(sstic_init);
module_exit(sstic_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sstic team");
MODULE_DESCRIPTION("sstic driver");



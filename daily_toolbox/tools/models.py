from django.db import models


class Category(models.Model):
    """链接分类，sort 控制大类显示顺序"""

    name = models.CharField("分类名", max_length=50, unique=True)
    sort = models.IntegerField("排序", default=0)

    class Meta:
        ordering = ["sort", "id"]
        verbose_name = "链接分类"
        verbose_name_plural = "链接分类"

    def __str__(self):
        return self.name


class Link(models.Model):
    """常用链接：分类 / 名称 / 地址，sort 控制分类内条目顺序"""

    category = models.CharField("分类", max_length=50)
    name = models.CharField("名称", max_length=100)
    url = models.CharField("地址", max_length=500)
    sort = models.IntegerField("排序", default=0)
    created_at = models.DateTimeField("创建时间", auto_now_add=True)

    class Meta:
        ordering = ["category", "sort", "id"]
        verbose_name = "常用链接"
        verbose_name_plural = "常用链接"

    def __str__(self):
        return f"[{self.category}] {self.name}"

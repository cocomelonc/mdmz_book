# MD MZ Book

Why is the book called that? **MD** - means **M**alware **D**evelopment, The **MZ** signature is a signature used by the MS-DOS relocatable `16-bit` EXE format and its still present in today's PE files for backwards compatibility, also **MD MZ** means **M**y **D**aughter **M**unira **Z**hassulankyzy.     

### versions and translations

[MD MZ Book first version (2022)](https://cocomelonc.github.io/book/2022/07/16/mybook.html)     
[MD MZ Book second version (2024)](https://cocomelonc.github.io/book/2024/11/29/mybook-2.html)      

This repository was created at the request of my readers to fix errors and create translations into other languages.      

You are welcome to contribute and make pull requests =^..^=!     

### create pdf

Use [pandoc](https://github.com/jgm/pandoc) command:    

```bash
pandoc -f markdown-implicit_figures --pdf-engine=xelatex -V mainfont="Amiri" -V colorlinks=true -V linkcolor=blue -o mdmz_book.pdf 1-intro.md 2-maldev.md .... 101-finall.md --mathjax
```

Main font:     

[Amiri](https://fonts.google.com/specimen/Amiri)      
---
title: "Post: Standard"
categories:
  - Blog
tags:
  - Post Formats
  - readability
  - standard
---

# Title Header (H1 header)

### Introduction (H3 header)

This is some placeholder text to show examples of Markdown formatting. We have [a full article template](https://github.com/do-community/do-article-templates) you can use when writing a DigitalOcean article. Please refer to our style and formatting guidelines for more detailed explanations: [do.co/style](do.co/style)

## Prerequisites (H2 header)

Before you begin this guide you'll need the following:

- Familiarity with [Markdown](https://daringfireball.net/projects/markdown/)

## Step 1 — Title Case

This is _italics_ and this is **bold**.

Here's a configuration file with a label:

```nginx
[label /etc/nginx/sites-available/default]
server {
    listen 80 default_server;
    . . .
}
```

Here's output from a command with a secondary label:

```
[secondary_label Output]
Could not connect to Redis at 127.0.0.1:6379: Connection refused
```

## Step 2 — Title Case

This is `inline code`. This is a <^>variable<^>. This is an `<^>in-line code variable<^>`.

This is a non-root user command example:

```command
sudo apt-get update
```

This is a root command example:

```super_user
adduser sammy
```

This is a custom prefix command example:

```custom_prefix(mysql>)
FLUSH PRIVILEGES;
```

## Step 3 — Title Case

Here's how to include an image:

<figure>
	<center><a href="http://farm9.staticflickr.com/8426/7758832526_cc8f681e48_b.jpg"><img src="http://farm9.staticflickr.com/8426/7758832526_cc8f681e48_b.jpg"></a></center>
	<!--<figcaption><a title="Tes">Test</a>.</figcaption>-->
</figure>

## Text alignment

Align text blocks with the following classes.

Left aligned text `.text-left`
{: .text-left}

```markdown
Left aligned text
{: .text-left}
```

---

Center aligned text. `.text-center`
{: .text-center}

```markdown
Center aligned text.
{: .text-center}
```

---

Right aligned text. `.text-right`
{: .text-right}

```markdown
Right aligned text.
{: .text-right}
```

---

**Justified text.** `.text-justify` Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque vel eleifend odio, eu elementum purus. In hac habitasse platea dictumst. Fusce sed sapien eleifend, sollicitudin neque non, faucibus est. Proin tempus nisi eu arcu facilisis, eget venenatis eros consequat.
{: .text-justify}

```markdown
Justified text.
{: .text-justify}
```

---

No wrap text. `.text-nowrap`
{: .text-nowrap}

```markdown
No wrap text.
{: .text-nowrap}
```

## Image alignment

Position images with the following classes.

![image-center]({{ "/assets/images/image-alignment-580x300.jpg" | relative_url }}){: .align-center}

The image above happens to be **centered**.

```markdown
![image-center](/assets/images/filename.jpg){: .align-center}
```

---

![image-left]({{ "/assets/images/image-alignment-150x150.jpg" | relative_url }}){: .align-left} The rest of this paragraph is filler for the sake of seeing the text wrap around the 150×150 image, which is **left aligned**. There should be plenty of room above, below, and to the right of the image. Just look at him there --- Hey guy! Way to rock that left side. I don't care what the right aligned image says, you look great. Don't let anyone else tell you differently.

```markdown
![image-left](/assets/images/filename.jpg){: .align-left}
```

---

![image-right]({{ "/assets/images/image-alignment-300x200.jpg" | relative_url }}){: .align-right}

And now we're going to shift things to the **right align**. Again, there should be plenty of room above, below, and to the left of the image. Just look at him there --- Hey guy! Way to rock that right side. I don't care what the left aligned image says, you look great. Don't let anyone else tell you differently.

```markdown
![image-right](/assets/images/filename.jpg){: .align-right}
```

---

![full]({{ "/assets/images/image-alignment-1200x4002.jpg" | relative_url }})
{: .full}

The image above should extend outside of the parent container on right.

```markdown
![full](/assets/images/filename.jpg)
{: .full}
```

## Buttons

Make any link standout more when applying the `.btn .btn--primary` classes.

```html
<a href="#" class="btn btn--primary">Link Text</a>
```

| Button Type   | Example | Class | Kramdown |
| ------        | ------- | ----- | ------- |
| Default       | [Text](#link){: .btn} | `.btn` | `[Text](#link){: .btn}` |
| Primary       | [Text](#link){: .btn .btn--primary} | `.btn .btn--primary` | `[Text](#link){: .btn .btn--primary}` |
| Success       | [Text](#link){: .btn .btn--success} | `.btn .btn--success` | `[Text](#link){: .btn .btn--success}` |
| Warning       | [Text](#link){: .btn .btn--warning} | `.btn .btn--warning` | `[Text](#link){: .btn .btn--warning}` |
| Danger        | [Text](#link){: .btn .btn--danger} | `.btn .btn--danger` | `[Text](#link){: .btn .btn--danger}` |
| Info          | [Text](#link){: .btn .btn--info} | `.btn .btn--info` | `[Text](#link){: .btn .btn--info}` |
| Inverse       | [Text](#link){: .btn .btn--inverse} | `.btn .btn--inverse` | `[Text](#link){: .btn .btn--inverse}` |
| Light Outline | [Text](#link){: .btn .btn--light-outline} | `.btn .btn--light-outline` | `[Text](#link){: .btn .btn--light-outline}` |

| Button Size | Example | Class | Kramdown |
| ----------- | ------- | ----- | -------- |
| X-Large     | [X-Large Button](#){: .btn .btn--primary .btn--x-large} | `.btn .btn--primary .btn--x-large` | `[Text](#link){: .btn .btn--primary .btn--x-large}` |
| Large       | [Large Button](#){: .btn .btn--primary .btn--large} | `.btn .btn--primary .btn--large` | `[Text](#link){: .btn .btn--primary .btn--large}` |
| Default     | [Default Button](#){: .btn .btn--primary} | `.btn .btn--primary` | `[Text](#link){: .btn .btn--primary }` |
| Small       | [Small Button](#){: .btn .btn--primary .btn--small} | `.btn .btn--primary .btn--small` | `[Text](#link){: .btn .btn--primary .btn--small}` |

## Notices

Call attention to a block of text.

| Notice Type | Class              |
| ----------- | -----              |
| Default     | `.notice`          |
| Primary     | `.notice--primary` |
| Info        | `.notice--info`    |
| Warning     | `.notice--warning` |
| Success     | `.notice--success` |
| Danger      | `.notice--danger`  |

**Watch out!** This paragraph of text has been [emphasized](#) with the `{: .notice}` class.
{: .notice}

**Watch out!** This paragraph of text has been [emphasized](#) with the `{: .notice--primary}` class.
{: .notice--primary}

**Watch out!** This paragraph of text has been [emphasized](#) with the `{: .notice--info}` class.
{: .notice--info}

**Watch out!** This paragraph of text has been [emphasized](#) with the `{: .notice--warning}` class.
{: .notice--warning}

**Watch out!** This paragraph of text has been [emphasized](#) with the `{: .notice--success}` class.
{: .notice--success}

**Watch out!** This paragraph of text has been [emphasized](#) with the `{: .notice--danger}` class.
{: .notice--danger}

{% capture notice-text %}
You can also add the `.notice` class to a `<div>` element.

* Bullet point 1
* Bullet point 2
{% endcapture %}

## Conclusion

Please refer to our [writing guidelines](http://do.co/style) for more detailed explanations on our style and formatting.

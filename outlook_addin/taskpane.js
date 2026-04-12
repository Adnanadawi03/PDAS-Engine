// taskpane.js
Office.onReady(() => {
  document.getElementById("scanMessage").onclick = scanMessage;
});

const API_BASE = "https://3903512bf446.ngrok-free.app";

async function scanMessage() {
  const statusEl = document.getElementById("status");
  statusEl.innerText = "جاري الفحص...";

  try {
    const item = Office.context.mailbox.item;
    // 1) احصل على نص الرسالة بصيغة HTML (تحتوي على روابط)
    item.getAllInternetHeadersAsync(async (hdrResult) => {
      // بديل: نستخدم getBodyAsync لو تريد نص الرسالة
      Office.context.mailbox.item.getBodyAsync(Office.CoercionType.Html, async (bodyResult) => {
        if (bodyResult.status === Office.AsyncResultStatus.Succeeded) {
          const html = bodyResult.value;
          const urls = extractUrls(html);
          statusEl.innerText = `تم العثور على ${urls.length} روابط — جارِ فحصها...`;

          // فحص كل رابط
          for (const u of urls) {
            try {
              const resp = await fetch(`${API_BASE}/scan/url`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: u })
              });
              const data = await resp.json();
              if (data.verdict === "block") {
                await showBlockDialog(u, "url");
                // لا نكسر الحلقة؛ لكن يمكنك إن أردت التوقف عند أول Block
              }
            } catch (e) {
              console.error("scan url error", e);
            }
          }

          // الآن تفحص المرفقات (إن وجدت)
          const atts = item.attachments || [];
          statusEl.innerText = `فحص ${urls.length} روابط و ${atts.length} مرفقات...`;

          for (const a of atts) {
            // فقط المرفقات من النوع "file"
            if (a && a.contentType !== "item") {
              await scanAttachment(a);
            }
          }

          statusEl.innerText = "الفحص انتهى.";
        } else {
          statusEl.innerText = "فشل الحصول على محتوى الرسالة.";
        }
      });
    });

  } catch (err) {
    console.error(err);
    document.getElementById("status").innerText = "حدث خطأ أثناء الفحص.";
  }
}

function extractUrls(html) {
  const re = /https?:\/\/[^\s"'>]+/gmi;
  const matches = html.match(re) || [];
  // إرجاع روابط فريدة
  return Array.from(new Set(matches));
}

async function scanAttachment(att) {
  return new Promise((resolve) => {
    // الحصول على محتوى المرفق كـ base64 (Office API)
    Office.context.mailbox.getCallbackTokenAsync({ isRest: true }, (tokenResult) => {
      // بعض بيئات Outlook تسمح مباشرة getAttachmentContentAsync:
      if (Office.context.mailbox.item.getAttachmentContentAsync) {
        Office.context.mailbox.item.getAttachmentContentAsync(att.id, async (result) => {
          if (result.status === Office.AsyncResultStatus.Succeeded) {
            const content = result.value.content; // base64
            const format = result.value.format; // "base64" أو "raw"
            const filename = att.name || ("attachment_" + att.id);

            try {
              // تحويل base64 إلى blob وارساله ك multipart/form-data
              const blob = base64ToBlob(content);
              const form = new FormData();
              form.append("file", blob, filename);

              const resp = await fetch(`${API_BASE}/scan/file`, {
                method: "POST",
                body: form
              });
              const data = await resp.json();
              if (data.verdict === "block") {
                await showBlockDialog(filename, "attachment");
              }
            } catch (e) {
              console.error("attachment scan error", e);
            }
          } else {
            console.warn("getAttachmentContentAsync failed", result);
          }
          resolve();
        });
      } else {
        // لو ال API غير متاح في العميل، نعرض رسالة توجيه للمستخدم
        alert("لا يمكن الوصول إلى محتوى المرفقات في هذا العميل. الرجاء تحميل المرفق وافحصه يدوياً.");
        resolve();
      }
    });
  });
}

function base64ToBlob(base64) {
  const byteCharacters = atob(base64);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  return new Blob([byteArray]);
}

function showBlockDialog(target, type) {
  return new Promise((resolve) => {
    const message = (type === "url")
      ? `تم الكشف عن رابط خبيث: ${target}\nتم منعه لأمانك.`
      : `المرفق "${target}" مصنّف خبيث. نوصي بعدم فتحه وحذفه.`;
    Office.context.ui.displayDialogAsync("", { height: 30, width: 40 }, (asyncResult) => {
      // سهل: بدلاً من نافذة dialog مع محتوى خارجي، نستخدم alert داخل taskpane
      alert(message);
      resolve();
    });
  });
}

const {
  Document, Packer, Paragraph, TextRun, ImageRun,
  AlignmentType, BorderStyle, PageNumber, Header, Footer
} = require('docx');
const fs = require('fs');

const logoBuffer = fs.readFileSync('C:\\Users\\APOORVA SHARMA\\OneDrive\\Desktop\\Final Year Project\\image.png');
const inch = (n) => Math.round(n * 1440);

function centred(children, spacingBefore = 0, spacingAfter = 0) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: spacingBefore, after: spacingAfter },
    children
  });
}

function tnr(text, { size = 24, bold = false, italics = false } = {}) {
  return new TextRun({ text, font: "Times New Roman", size, bold, italics });
}

// Header: two sides separated by a tab, with bottom rule
// Left: "SecureNet — Network Intrusion Detection System"
// Right: "Final Year B.Tech Project Report"
// Tab stop at right margin (content width = 8.27 - 1.25 - 1.0 = 6.02 inches = 8669 DXA)
const coverHeader = new Header({
  children: [
    new Paragraph({
      alignment: AlignmentType.LEFT,
      border: {
        bottom: { style: BorderStyle.SINGLE, size: 4, color: "000000", space: 1 }
      },
      tabStops: [
        { type: "right", position: inch(6.02) }
      ],
      spacing: { after: 0 },
      children: [
        new TextRun({ text: "SecureNet \u2014 Network Intrusion Detection System", font: "Times New Roman", size: 18, italics: true }),
        new TextRun({ text: "\t", font: "Times New Roman", size: 18 }),
        new TextRun({ text: "Final Year B.Tech Project Report", font: "Times New Roman", size: 18, italics: true })
      ]
    })
  ]
});

const coverFooter = new Footer({
  children: [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [
        new TextRun({ font: "Times New Roman", size: 24, children: [PageNumber.CURRENT] })
      ]
    })
  ]
});

const doc = new Document({
  sections: [{
    properties: {
      page: {
        size: { width: inch(8.27), height: inch(11.69) },
        margin: {
          top:    inch(1.0),
          bottom: inch(1.0),
          left:   inch(1.25),
          right:  inch(1.0),
          header: inch(0.4),
          footer: inch(0.5)
        }
      }
    },
    headers: { default: coverHeader },
    footers: { default: coverFooter },
    children: [

      // Title — 22pt Bold Centred
      // spacingBefore drives vertical centering; use 0 — the title starts near top
      centred([tnr("SecureNeT: NETWORK", { size: 44, bold: true })], 0, 0),
      centred([tnr("INTRUSION DETECTION SYSTEM", { size: 44, bold: true })], 0, inch(0.3)),

      // Italic subtitle
      centred([tnr("A Project Report submitted in partial fulfilment of the requirements for", { size: 24, italics: true })], 0, 0),
      centred([tnr("the award of the degree of", { size: 24, italics: true })], 0, inch(0.2)),

      // Degree
      centred([tnr("Bachelor of Technology", { size: 28, bold: true })], 0, 0),
      centred([tnr("in", { size: 24, italics: true })], 0, 0),
      centred([tnr("Computer Science and Business Systems", { size: 24, bold: true })], 0, inch(0.3)),

      // Submitted by
      centred([tnr("Submitted by", { size: 24, italics: true })], 0, inch(0.1)),

      // Authors
      centred([tnr("Apoorva Sharma", { size: 24, bold: true })], 0, 0),
      centred([tnr("Roll No: 221001020011", { size: 24 })], 0, inch(0.12)),
      centred([tnr("Srinjana Deb", { size: 24, bold: true })], 0, 0),
      centred([tnr("Roll No: 221001020019", { size: 24 })], 0, inch(0.3)),

      // Logo — 2.65 × 1.9 inches, centred
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 0, after: inch(0.35) },
        children: [
          new ImageRun({
            data: logoBuffer,
            type: "png",
            transformation: {
              width:  Math.round(2.65 * 96),
              height: Math.round(1.9 * 96)
            }
          })
        ]
      }),

      // Department
      centred([tnr("DEPARTMENT OF COMPUTER SCIENCE AND BUSINESS", { size: 24, bold: true })], 0, 0),
      centred([tnr("SYSTEMS", { size: 24, bold: true })], 0, 0),
      centred([tnr("Techno India University", { size: 24 })], 0, 0),
      centred([tnr("Kolkata, West Bengal \u2013 700091\u2003Academic Year: 2025-2026", { size: 24 })], 0, 0),

    ]
  }]
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync("./SecureNet_Cover_Page.docx", buffer);
  console.log(`Done. Size: ${buffer.length} bytes`);
});

